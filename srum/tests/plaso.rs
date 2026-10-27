//! plaso's `SRUDB.dat` (Apache-2.0, `tests/fixtures/plaso/`, stored
//! gzip-compressed): the entries and values plaso's own SRUM tests expect.

use common::time::Ts;
use srum::{Entry, Kind, Srum};

fn srum() -> Srum {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/plaso/SRUDB.dat.gz"
    ))
    .unwrap();
    let data = {
        let mut data = Vec::new();
        std::io::Read::read_to_end(
            &mut common::gzip::Decoder::new(compressed.as_slice()),
            &mut data,
        )
        .unwrap();
        data
    };
    srum::read(&data).unwrap()
}

fn iso(ts: Option<Ts>) -> String {
    ts.and_then(|ts| ts.to_iso8601()).unwrap_or_default()
}

fn find(srum: &Srum, kind: Kind, id: i64) -> &Entry {
    srum.entries
        .iter()
        .find(|e| e.kind == Some(kind) && e.id == Some(id))
        .unwrap()
}

#[test]
fn what_plaso_expects() {
    let srum = srum();
    // plaso reads these three providers: 18,283 events.
    let count = |kind| srum.entries.iter().filter(|e| e.kind == Some(kind)).count();
    assert_eq!(
        (
            count(Kind::NetworkUsage),
            count(Kind::ApplicationUsage),
            count(Kind::NetworkConnectivity)
        ),
        (1840, 16183, 260)
    );

    let usage = find(&srum, Kind::ApplicationUsage, 22167);
    assert_eq!(usage.app.as_deref(), Some("Memory Compression"));
    assert_eq!(iso(usage.time), "2017-11-05T11:32:00.0000000Z");

    let network = find(&srum, Kind::NetworkUsage, 3495);
    assert_eq!(network.app.as_deref(), Some("DiagTrack"));
    assert_eq!(network.user.as_deref(), Some("S-1-5-18"));
    assert_eq!(
        network.value("BytesSent").and_then(ese::Value::as_i64),
        Some(2076)
    );
    assert_eq!(
        network.value("InterfaceLuid").and_then(ese::Value::as_i64),
        Some(1_689_399_632_855_040)
    );
    assert_eq!(iso(network.time), "2017-11-05T11:32:00.0000000Z");

    let connectivity = find(&srum, Kind::NetworkConnectivity, 501);
    // plaso prints the raw id: the map doesn't name it.
    assert_eq!(
        (connectivity.app_id, connectivity.app.as_deref()),
        (Some(1), None)
    );
    assert_eq!(iso(connectivity.time), "2017-11-05T13:33:00.0000000Z");
    let times = connectivity.times();
    assert_eq!(times.len(), 1);
    assert_eq!(
        (times[0].0, iso(Some(times[0].1))),
        (
            "ConnectStartTime",
            "2017-11-05T10:30:48.1679714Z".to_owned()
        )
    );
}

#[test]
fn every_provider_table_is_read() {
    let srum = srum();
    let tables: std::collections::BTreeSet<&str> =
        srum.entries.iter().map(|e| e.table.as_str()).collect();
    assert!(tables.contains("{5C8CF1C7-7257-4F13-B223-970EF5939312}"));
    // An unknown provider is kept, unnamed.
    let unknown = srum
        .entries
        .iter()
        .find(|e| e.table == "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}")
        .unwrap();
    assert_eq!(unknown.kind, None);
    assert!(unknown.value("BinaryData").is_some());
    assert_eq!(srum.problems, Vec::<String>::new());
}
