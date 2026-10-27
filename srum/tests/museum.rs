//! Real Windows 11 (dirty), Windows 10 and Windows Server 2022 databases
//! (DFIRArtifactMuseum, MIT; `tests/fixtures/museum/`), against every entry
//! decoded independently from dissect.esedb's values.

use std::collections::HashMap;
use std::io::Read;

use srum::{Kind, Srum, Time};

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

fn unescape(field: &str) -> String {
    let mut out = String::new();
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Every entry against the expected line with its table and `AutoIncId`.
fn check(name: &str) -> Srum {
    let srum = srum::read(&fixture(&format!("{name}.dat.gz"))).unwrap();
    let expected = String::from_utf8(fixture(&format!("{name}.dissect.tsv.gz"))).unwrap();
    let expected: HashMap<(String, i64), Vec<String>> = expected
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<String> = line.split('\t').map(unescape).collect();
            ((fields[0].clone(), fields[1].parse().unwrap()), fields)
        })
        .collect();
    assert_eq!(srum.entries.len(), expected.len());
    for entry in &srum.entries {
        let want = &expected[&(entry.table.clone(), entry.id.unwrap())];
        let iso = |time: Option<Time>| time.map(Time::to_iso8601).unwrap_or_default();
        // the expected name is the whole IdBlob; the entry splits the `!!` form
        let app = entry.app.as_ref().map_or(String::new(), |app| {
            if want[3].starts_with("!!") {
                want[3].clone()
            } else {
                app.name.clone()
            }
        });
        let times = entry
            .times()
            .iter()
            .map(|(column, time)| format!("{column}={}", iso(*time)))
            .collect::<Vec<_>>()
            .join(";");
        let got = [
            iso(entry.time),
            app,
            entry.user.clone().unwrap_or_default(),
            times,
        ];
        assert_eq!(got.as_slice(), &want[2..], "{} {:?}", entry.table, entry.id);
    }
    srum
}

#[test]
fn windows_11_dirty() {
    let srum = check("win11_rathbunvm_dirty");
    assert!(srum.dirty);
    assert!(srum.problems[0].starts_with("dirty shutdown"));
    let timeline = |kind| srum.entries.iter().filter(|e| e.kind == Some(kind)).count();
    assert_eq!(timeline(Kind::ApplicationTimeline), 791);
    assert_eq!(timeline(Kind::VfuProvider), 33);
}

#[test]
fn windows_10() {
    let srum = check("win10_rathbunvm");
    assert!(!srum.dirty);
    let network = srum
        .entries
        .iter()
        .find(|e| e.kind == Some(Kind::NetworkUsage))
        .unwrap();
    assert!(network.interface_type().is_some());
}

#[test]
fn windows_server_2022() {
    let srum = check("server2022_aptsimulatorvm");
    for kind in [Kind::ProcessorTime, Kind::SizeInBytes, Kind::TotalUsed] {
        assert!(
            srum.entries.iter().any(|e| e.kind == Some(kind)),
            "{kind:?}"
        );
    }
    // the volumes and adapters those providers measure are type 4 ids
    let objects = srum
        .ids
        .iter()
        .filter(|id| id.kind == srum::IdKind::Object)
        .count();
    assert!(objects > 0);
}
