//! How each value of a real database was read, and its bytes: the Windows 11 database of
//! `tests/fixtures/museum/` (DFIRArtifactMuseum, MIT), whose timeline table has many NULLs.

use std::io::Read;

use srum::{Context, Kind, Options, Value, ValueState};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/museum/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let compressed = std::fs::read(path).unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn nulls_are_told_from_values_and_bytes_are_kept() {
    let data = fixture("win11_rathbunvm_dirty.dat.gz");
    let options = Options {
        value_states: true,
        raw_values: true,
    };
    let srum = srum::read_with_options(&data, &Context::default(), &options).unwrap();
    let plain = srum::read(&data).unwrap();
    assert_eq!(srum.entries.len(), plain.entries.len());

    let mut nulls = 0;
    for (entry, same) in srum.entries.iter().zip(&plain.entries) {
        // the values are those read without the options
        assert_eq!(entry.values, same.values);
        assert_eq!(same.cells, Vec::<srum::Cell>::new());
        assert_eq!(same.state("AutoIncId"), None);
        for cell in &entry.cells {
            match cell.state {
                // a NULL has no bytes: none are made up
                ValueState::Null => {
                    nulls += 1;
                    assert_eq!(cell.raw, None, "{}", cell.column);
                }
                ValueState::Parsed => assert!(cell.raw.is_some(), "{}", cell.column),
                other => panic!("{}: {other:?} in {}", cell.column, entry.table),
            }
        }
        // the id's bytes are the id, a Long
        let id = i32::try_from(entry.id.unwrap()).unwrap();
        assert_eq!(entry.raw("AutoIncId"), Some(&id.to_le_bytes()[..]));
        assert_eq!(entry.state("TimeStamp"), Some(ValueState::Parsed));
        assert_eq!(entry.state("NoSuchColumn"), Some(ValueState::Absent));
        assert_eq!(entry.raw("NoSuchColumn"), None);
    }
    assert!(nulls > 10_000, "{nulls}");

    // a NULL in the database: no value, no bytes
    let timeline = srum
        .entries
        .iter()
        .find(|e| {
            e.kind == Some(Kind::ApplicationTimeline) && e.value("AudioInS") == Some(&Value::Null)
        })
        .unwrap();
    assert_eq!(timeline.state("AudioInS"), Some(ValueState::Null));
    assert_eq!(timeline.raw("AudioInS"), None);
}

#[test]
fn bytes_are_kept_only_when_asked_for() {
    let data = fixture("win11_rathbunvm_dirty.dat.gz");
    let options = Options {
        value_states: true,
        raw_values: false,
    };
    let srum = srum::read_with_options(&data, &Context::default(), &options).unwrap();
    let entry = &srum.entries[0];
    assert_eq!(entry.state("AutoIncId"), Some(ValueState::Parsed));
    assert!(entry.cells.iter().all(|cell| cell.raw.is_none()));
}
