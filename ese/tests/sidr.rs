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

//! SIDR's test `Windows.edb` (Apache-2.0, a Windows 10 search index,
//! downloaded by `tests/fetch-sidr.sh`; skipped without it): Windows 10
//! compresses long values without flagging them in the record, and every
//! one reads whole.

#[test]
fn windows_10_compressed_long_values() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sidr/Windows.edb"
    );
    let Ok(data) = std::fs::read(path) else {
        return;
    };
    let db = ese::Database::open(&data).unwrap();
    let mut rows = db.rows("SystemIndex_PropertyStore").unwrap();
    assert_eq!(rows.by_ref().count(), 1182);
    assert_eq!(rows.problems(), &[] as &[String]);
}
