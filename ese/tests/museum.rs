// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
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

//! DFIRArtifactMuseum's dirty Windows 10 search index (MIT, `tests/fixtures/museum/NOTICE`):
//! copied from a running system, its property store's branch pages are older than its leaves.
//! libesedb's esedbexport reads 930 property-store rows (`WorkID` 1 to 935 without 547, 548,
//! 549, 577 and 579) and 935 gatherer rows; the branch walk alone stops after `WorkID` 700.

use std::collections::BTreeSet;
use std::io::Read;

use ese::{Database, Value};

fn fixture() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/museum/Windows.edb.gz"
    );
    let compressed = std::fs::read(path).unwrap();
    let mut plain = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut plain)
        .unwrap();
    plain
}

#[test]
fn leaves_past_the_last_branch_entry_are_read_through_the_sibling_chain() {
    let data = fixture();
    let db = Database::open(&data).unwrap();
    let table = db.table("SystemIndex_PropertyStore").unwrap();
    let mut rows = db.rows("SystemIndex_PropertyStore").unwrap();
    let ids: BTreeSet<i64> = rows
        .by_ref()
        .map(|row| row.get(table, "WorkID").and_then(Value::as_i64).unwrap())
        .collect();
    let expected: BTreeSet<i64> = (1..=935)
        .filter(|id| ![547, 548, 549, 577, 579].contains(id))
        .collect();
    assert_eq!(ids.len(), 930);
    assert_eq!(ids, expected);
    let problems = rows.problems();
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert!(
        problems[0].contains("a leaf page no branch page reaches"),
        "{problems:?}"
    );
    assert_eq!(
        problems[1],
        "8 leaf pages were read through the sibling chain; no branch page reaches them"
    );
    // The gatherer tables were complete before and stay so.
    let mut gthr = db.rows("SystemIndex_Gthr").unwrap();
    assert_eq!(gthr.by_ref().count(), 935);
    assert_eq!(gthr.problems(), &[] as &[String]);
    assert_eq!(db.rows("SystemIndex_GthrPth").unwrap().count(), 174);
}
