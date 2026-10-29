//! Any input gives entries, problems or an error, never a panic.

use proptest::prelude::*;

fn fixture() -> Vec<u8> {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/plaso/SRUDB.dat.gz"
    ))
    .unwrap();
    {
        let mut data = Vec::new();
        std::io::Read::read_to_end(
            &mut common::gzip::Decoder::new(compressed.as_slice()),
            &mut data,
        )
        .unwrap();
        data
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..70_000)) {
        let _ = srum::read(&data);
    }

    #[test]
    fn the_database_damaged_with_value_states_and_bytes(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..200)) {
        let mut data = fixture();
        for (at, byte) in flips {
            let at = at % data.len();
            data[at] = byte;
        }
        let options = srum::Options { value_states: true, raw_values: true };
        if let Ok(srum) = srum::read_with_options(&data, &srum::Context::default(), &options) {
            // a value that wasn't read is reported
            let damaged = srum.entries.iter().flat_map(|e| &e.cells).any(|c| c.state == srum::ValueState::Damaged);
            prop_assert!(!damaged || !srum.problems.is_empty());
        }
    }

    #[test]
    fn the_database_damaged(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..200)) {
        let mut data = fixture();
        for (at, byte) in flips {
            let at = at % data.len();
            data[at] = byte;
        }
        let _ = srum::read(&data);
    }
}

#[test]
fn not_srum() {
    assert!(srum::read(b"").is_err());
}
