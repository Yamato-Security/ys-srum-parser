// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Cyber Experts
//
// This file is changed from Sootmark/ese (https://github.com/Sootmark/ese), whose code is under the
// MIT License or the Apache License 2.0 (LICENSE-MIT, LICENSE-APACHE).
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! B+-trees, walked from the root in key order one leaf entry at a time.
//!
//! Damage never stops the walk: a page that can't be read, belongs to
//! another tree, is a space tree page, or was already visited (a cycle, or a
//! page claimed twice) is reported and skipped, and so is an entry that
//! doesn't fit its page. Every page is visited at most once per walk, so a
//! walk ends, and memory stays proportional to the file. Defunct entries
//! (deleted, not yet cleaned up) are skipped, as ESE skips them.
//!
//! Leaf pages also link to their right-hand siblings. After a dirty shutdown
//! the branch pages on disk can be older than the leaves below them: leaves
//! added after the branch page was last written are reached by no branch
//! entry, only by the sibling link of the leaf before them. Missing leaves
//! are followed between branch-referenced leaves as well as after the last
//! one, in key order. Every recovered page must be a leaf of this tree;
//! recovery and invalid sibling links are reported. This is not log replay
//! and does not establish whether recovered rows were committed.

use std::collections::HashSet;

use crate::page::{Node, Page};
use crate::pager::Pages;

/// A leaf entry, and the page holding it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry<'a> {
    pub(crate) page: u32,
    pub(crate) node: Node<'a>,
}

/// A page being walked: its entries are tags 1 and up.
struct Frame<'a> {
    page: Page<'a>,
    next_tag: usize,
    tag_count: usize,
}

/// A walk through one B+-tree, in key order.
pub(crate) struct Cursor<'a> {
    pages: &'a Pages<'a>,
    /// The tree's object identifier, from its root page; every page of the
    /// tree carries it.
    object_id: Option<u32>,
    stack: Vec<Frame<'a>>,
    visited: HashSet<u32>,
    /// Pages reachable through branch entries. Knowing these before walking
    /// lets us fill sibling-chain gaps in order without reading a later
    /// branch child twice or hiding duplicate branch references.
    referenced: HashSet<u32>,
    /// Leaf pages read through the sibling chain, and whether their count
    /// was reported.
    chained: u32,
    chain_reported: bool,
    /// What went wrong on the way, in the order met.
    pub(crate) problems: Vec<String>,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(pages: &'a Pages<'a>, root: u32) -> Self {
        let mut cursor = Self {
            pages,
            object_id: None,
            stack: Vec::new(),
            visited: HashSet::new(),
            referenced: Self::branch_references(pages, root),
            chained: 0,
            chain_reported: false,
            problems: Vec::new(),
        };
        cursor.descend(root);
        cursor
    }

    /// Discover branch references without reading leaf records. This bounded
    /// header/branch pass is also used for long-value trees, whose records
    /// must remain in key order. The normal walk reports damaged branches.
    fn branch_references(pages: &Pages<'_>, root: u32) -> HashSet<u32> {
        let mut referenced = HashSet::new();
        let mut pending = vec![root];
        let object_id = pages.get(root).ok().map(|page| page.fdp_object_id());
        while let Some(number) = pending.pop() {
            if !referenced.insert(number) {
                continue;
            }
            let Ok(page) = pages.get(number) else {
                continue;
            };
            let flags = page.flags();
            if Some(page.fdp_object_id()) != object_id
                || flags.is_leaf()
                || flags.is_space_tree()
                || flags.is_empty()
                || page.is_blank()
            {
                continue;
            }
            let Ok(count) = page.tag_count() else {
                continue;
            };
            for index in 1..count {
                if let Ok(node) = page.node(index)
                    && !node.flags.is_defunct()
                    && let Ok(child) = page.child(&node)
                {
                    pending.push(child);
                }
            }
        }
        referenced
    }

    /// Follow a missing sibling immediately after its predecessor, even if
    /// the predecessor has no live records. Branch-referenced siblings are
    /// left for the normal walk; revisiting a page is a broken chain.
    fn sibling(&mut self, page: Page<'a>) {
        let next = page.next_page();
        if next == 0 {
            return;
        }
        if self.visited.contains(&next) {
            self.problems.push(format!(
                "page {}: sibling link to page {next} forms a cycle or repeats a visited page",
                page.number
            ));
            return;
        }
        if self.referenced.contains(&next) {
            return;
        }
        let frame = match self.frame(next) {
            Ok(frame) => frame,
            Err(problem) => {
                self.problems.push(format!(
                    "page {}: invalid sibling link: {problem}",
                    page.number
                ));
                return;
            }
        };
        if !frame.page.flags().is_leaf() {
            self.problems.push(format!(
                "page {}: sibling page {next} is not a leaf",
                page.number
            ));
            return;
        }
        if self.chained == 0 {
            self.problems.push(format!(
                "page {next}: a leaf page no branch page reaches; reading the sibling chain \
                 (the branch pages may be stale after a dirty shutdown)"
            ));
        }
        self.chained += 1;
        self.stack.push(frame);
    }

    /// Push page `number`, if it can be read as a page of this tree.
    fn descend(&mut self, number: u32) {
        match self.frame(number) {
            Ok(frame) => self.stack.push(frame),
            Err(problem) => self.problems.push(problem),
        }
    }

    fn frame(&mut self, number: u32) -> Result<Frame<'a>, String> {
        if !self.visited.insert(number) {
            return Err(format!(
                "page {number} reached twice in one tree (a cycle?)"
            ));
        }
        let page = self.pages.get(number)?;
        if page.is_blank() {
            return Err(format!("page {number} is blank (never written)"));
        }
        if let Some(problem) = self.pages.verify(&page) {
            self.problems.push(problem);
        }
        self.check_membership(&page)?;
        let flags = page.flags();
        if flags.is_space_tree() {
            return Err(format!(
                "page {number} is a space tree page, not a data page"
            ));
        }
        if flags.is_empty() {
            return Err(format!("page {number} is marked empty"));
        }
        Ok(Frame {
            page,
            next_tag: 1,
            tag_count: page.tag_count()?,
        })
    }

    /// Check that `page` belongs to this tree: the root sets the tree's
    /// object identifier, every other page must carry it.
    fn check_membership(&mut self, page: &Page) -> Result<(), String> {
        let object_id = page.fdp_object_id();
        match self.object_id {
            None => {
                self.object_id = Some(object_id);
                if !page.flags().is_root() {
                    self.problems.push(format!(
                        "page {}: a tree's root page without the root flag",
                        page.number
                    ));
                }
                Ok(())
            }
            Some(expected) if expected != object_id => Err(format!(
                "page {} belongs to object {object_id}, not to this tree's {expected}",
                page.number
            )),
            Some(_) => Ok(()),
        }
    }

    /// The next leaf entry in key order, or `None` at the end of the tree.
    pub(crate) fn next_entry(&mut self) -> Option<Entry<'a>> {
        while let Some(frame) = self.stack.last_mut() {
            if frame.next_tag >= frame.tag_count {
                let page = frame.page;
                self.stack.pop();
                if page.flags().is_leaf() {
                    self.sibling(page);
                }
                continue;
            }
            let index = frame.next_tag;
            frame.next_tag += 1;
            let page = frame.page;
            let node = match page.node(index) {
                Ok(node) => node,
                Err(problem) => {
                    self.problems.push(problem);
                    continue;
                }
            };
            if node.flags.is_defunct() {
                continue;
            }
            if page.flags().is_leaf() {
                return Some(Entry {
                    page: page.number,
                    node,
                });
            }
            match page.child(&node) {
                Ok(child) => self.descend(child),
                Err(problem) => self.problems.push(problem),
            }
        }
        if self.chained > 0 && !self.chain_reported {
            self.chain_reported = true;
            self.problems.push(format!(
                "{} leaf pages were read through the sibling chain; no branch page reaches them",
                self.chained
            ));
        }
        None
    }
}

impl<'a> Iterator for Cursor<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Entry<'a>> {
        self.next_entry()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::Header;

    const SIZE: usize = 4096;
    const OBJECT: u32 = 42;

    fn put(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    // A tiny tree with one byte of data per leaf, or a child pointer per branch node.
    fn page(flags: u32, next: u32, values: &[u32], defunct: bool) -> Vec<u8> {
        let mut bytes = vec![0; SIZE];
        put(&mut bytes, 20, next);
        put(&mut bytes, 24, OBJECT);
        put(&mut bytes, 36, flags);
        bytes[34..36].copy_from_slice(&((values.len() + 1) as u16).to_le_bytes());
        let mut offset = 0usize;
        for (index, value) in values.iter().enumerate() {
            let mut node = vec![0, 0]; // no key suffix
            if flags & 2 != 0 {
                node.push(*value as u8);
            } else {
                node.extend_from_slice(&value.to_le_bytes());
            }
            bytes[40 + offset..40 + offset + node.len()].copy_from_slice(&node);
            let tag = SIZE - 4 * (index + 2);
            bytes[tag..tag + 2].copy_from_slice(&(node.len() as u16).to_le_bytes());
            let tag_offset = offset as u16 | if defunct { 2 << 13 } else { 0 };
            bytes[tag + 2..tag + 4].copy_from_slice(&tag_offset.to_le_bytes());
            offset += node.len();
        }
        bytes
    }

    fn walk(pages: &[Vec<u8>]) -> (Vec<u8>, Vec<String>) {
        let mut file = vec![0; SIZE * 2];
        put(&mut file, 4, 0x89ab_cdef);
        put(&mut file, 8, 0x620);
        put(&mut file, 232, 0x14);
        put(&mut file, 236, SIZE as u32);
        for page in pages {
            file.extend_from_slice(page);
        }
        let header = Header::parse(&file, &mut Vec::new()).unwrap();
        let pages = Pages::new(&file, &header);
        let mut cursor = Cursor::new(&pages, 1);
        let data = cursor.by_ref().map(|entry| entry.node.data[0]).collect();
        (data, cursor.problems)
    }

    #[test]
    fn sibling_leaves_between_branch_children_keep_key_order() {
        let (rows, problems) = walk(&[
            page(1, 0, &[2, 4], false),
            page(2, 3, &[2], false),
            page(2, 4, &[3], false),
            page(2, 0, &[4], false),
        ]);
        assert_eq!(rows, [2, 3, 4]);
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("1 leaf pages were read"))
        );
        assert!(!problems.iter().any(|p| p.contains("reached twice")));
    }

    #[test]
    fn sibling_walk_continues_past_leaves_without_live_entries() {
        for values in [vec![], vec![3]] {
            let (rows, problems) = walk(&[
                page(1, 0, &[2], false),
                page(2, 3, &[2], false),
                page(2, 4, &values, true),
                page(2, 0, &[4], false),
            ]);
            assert_eq!(rows, [2, 4]);
            assert!(
                problems
                    .iter()
                    .any(|p| p.starts_with("2 leaf pages were read"))
            );
        }
    }

    #[test]
    fn sibling_links_cannot_descend_into_branch_pages() {
        let (rows, problems) = walk(&[
            page(1, 0, &[2], false),
            page(2, 3, &[2], false),
            page(0, 0, &[4], false),
            page(2, 0, &[99], false),
        ]);
        assert_eq!(rows, [2]);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("sibling") && p.contains("not a leaf"))
        );
        assert!(!problems.iter().any(|p| p.contains("leaf pages were read")));
    }

    #[test]
    fn sibling_cycles_are_reported_and_terminate() {
        let (rows, problems) = walk(&[
            page(1, 0, &[2], false),
            page(2, 3, &[2], false),
            page(2, 2, &[3], false),
        ]);
        assert_eq!(rows, [2, 3]);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("sibling") && p.contains("cycle"))
        );
    }

    #[test]
    fn sibling_links_cannot_read_foreign_or_out_of_range_pages() {
        for next in [3, 99] {
            let mut foreign = page(2, 0, &[99], false);
            put(&mut foreign, 24, OBJECT + 1);
            let (rows, problems) =
                walk(&[page(1, 0, &[2], false), page(2, next, &[2], false), foreign]);
            assert_eq!(rows, [2]);
            assert!(!problems.iter().any(|p| p.contains("leaf pages were read")));
            assert!(
                problems
                    .iter()
                    .any(|p| p.contains("belongs to object") || p.contains("outside the database"))
            );
        }
    }
}
