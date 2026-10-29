# ys-srum-parser

Yamato Security's maintained fork of Sootmark's [ese](https://github.com/Sootmark/ese) and
[srum](https://github.com/Sootmark/srum) crates (Florian Amette): a reader of ESE ("JET Blue")
databases, and on it the Windows System Resource Usage Monitor (`SRUDB.dat`) parser used by
[Juntei](https://github.com/Yamato-Security/juntei). Both upstream histories are kept (imported into
`ese/` and `srum/`), with their MIT OR Apache-2.0 license; each crate's README is upstream's,
updated for what the fork changed.

| Crate | Library | What it reads |
| --- | --- | --- |
| [`ys-srum-parser-ese`](ese/) | `ese` | ESE databases: header, checksums, B+-trees, the catalog, records, long values, compressed values |
| [`ys-srum-parser`](srum/) | `srum` | `SRUDB.dat`: every provider table, with programs, accounts, times and interfaces decoded |

## Why these crates

Reading SRUM is two problems: reading the ESE database, and turning its provider tables into
evidence. Both were compared on eleven real `SRUDB.dat` files (Windows 10 and 11, clean and left
dirty, Windows Server 2022; from DFIRArtifactMuseum, plaso and chainsaw's test data) against
[dissect.esedb](https://github.com/fox-it/dissect.esedb) 3.18 and libesedb 20260704, which agree on
all 1,235,675 values of the SRUM tables but for the 450,214 NULL fixed columns libesedb returns as
their filler bytes (it doesn't read the NULL bitmap).

The ESE readers in Rust, on the 56,292 rows of those databases' SRUM tables:

| Crate | Rows equal to dissect.esedb's | Notes |
| --- | --- | --- |
| **sootmark-ese 0.1.1** | **56,292 (100%)** | reads the catalog, the NULL bitmap, long values, multi-values, 7-bit and Xpress compression and all three checksum formats; no dependencies; no panic on 900 damaged copies |
| frnsc-esedb 0.3.0 | 31,752 (56%): 24,540 rows missing, 1,908 with other values | builds only against an unreleased forensic-rs 0.14; reads transaction logs and has deleted-record ideas; no panic on 900 damaged copies |
| ese-parser 0.1.9 (ac-rn/ese-rs) | 28,980 (51%) | every `IdBlob` read empty (so no program or account names), `LongLong` read unsigned, NULL fixed columns read as filler |
| ese-core 0.2.2 (SecurityRonin/ese-forensic) | 0 | its catalog reader finds no columns in real databases; its `srum-parser` 0.4.0 reads SRUM fields at fixed byte offsets instead, which breaks when Windows changes a table's columns |
| ese-parser 0.1.0 (icedracon) | – | header and raw pages only |

For the SRUM layer, sootmark-srum's model (every table and column kept from the catalog, unknown
tables still read, NULL kept apart from 0) was the base, extended with what an examiner expects:
the provider tables and names for them, `!!` program names split up, every FILETIME column read as
a time, interface types, and the names the `SOFTWARE` hive gives accounts and wireless networks.
chainsaw's SRUM output (GPL-3.0, through libesedb) truncates `TimeStamp` to the second, so 738
entries of its own test database come out a second early; this crate rounds to the millisecond.

What the fork adds and fixes:

| Change | Source |
| --- | --- |
| ESE: column type 18 (`UnsignedLongLong`, Windows 10 and later) read as `Value::U64`, not binary | fork (found in review) |
| ESE: a row reads at most 256 MiB of long values (`Rows::long_value_limit`): a crafted row referring to one long value many times made a copy per reference | fork (found in review) |
| ESE: Xpress match lengths saturate (they overflowed on 32-bit targets) | fork (found in review) |
| SRUM: 14 provider tables known (8 before), Windows Server 2022's four among them; `Kind::output_name` names each | fork |
| SRUM: every FILETIME column read as a time (`Entry::times`: `ConnectStartTime`, `EventTimestamp`, the timeline's `EndTime`, the VFU provider's `StartTime`/`EndTime`) | fork |
| SRUM: ids keep their type (`IdKind`: program, service, packaged app, SID, object), `!!name!time!x!description` names are split (`AppName`), a `UserId` resolves only to a SID | fork |
| SRUM: interface types from `InterfaceLuid` (`interface_type_name`) | Windows' ipifcons.h |
| SRUM: account and wireless network names from the `SOFTWARE` hive (`read_with`, `Context`; the caller reads the hive) | fork |
| SRUM: `TimeStamp` rounded to the millisecond; a local `Time` replaces sootmark-common's, so `ese` is the only dependency | fork |
| SRUM: a missing or damaged `SruDbIdMapTable` no longer fails the database; `dirty`, `tables` (every table and its rows) and unresolved ids are reported | fork |
| Tests on three real databases (Windows 11 left dirty, Windows 10, Windows Server 2022; DFIRArtifactMuseum, MIT), every entry checked | fork |
| One workspace and one CI (Linux, macOS, Windows, MSRV, wasm32, cargo-deny), actions pinned by commit | fork |
| The crates named after the repository (`ys-srum-parser`, `ys-srum-parser-ese`), version 1.0.0, edition 2024, Rust 1.99 | fork |

On the eleven databases, all 45,255 entries equal a decoding written independently from
dissect.esedb's values: time, program, account, FILETIME columns and every other value. 1,100
damaged copies of them read without a panic, a hang or an allocation over 1 GiB.

```rust
// names for accounts and wireless networks, read from the SOFTWARE hive by the caller
let mut context = srum::Context::default();
context.user_names.insert("S-1-5-21-…-1001".into(), "alice".into());
let srum = srum::read_with(&std::fs::read("SRUDB.dat")?, &context)?;
for entry in &srum.entries {
    let Some(kind) = entry.kind else { continue };
    let app = entry.app.as_ref().map(|app| app.name.as_str());
    println!("{} {:?} {:?} {:?} {:?}", kind.output_name(), entry.time, app, entry.user_name, entry.times());
}
if srum.dirty {
    eprintln!("dirty: changes still in SRU*.log are missing");
}
```

Use it from Cargo by commit (the crates are named after the repository, `ys-srum-parser` and
`ys-srum-parser-ese`, and keep their library names, `srum` and `ese`; they are not published, and
their versions are the fork's own: 1.0.0 since the rename; Rust 1.99, edition 2024):

```toml
srum = { package = "ys-srum-parser", git = "https://github.com/Yamato-Security/ys-srum-parser", rev = "<commit>" }
```

Not yet: replaying the transaction logs (`SRU*.log`) into a dirty database; recovering deleted
records and page slack; Xpress9 and Xpress10 values. Windows 11 24H2's databases (format revision
0x122 and later, whose page tags need masking) are read as the format documentation describes,
but no openly licensed one has been tested.

## Licence

MIT or Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`). The test databases keep their
licences: plaso's (Apache-2.0) and DFIRArtifactMuseum's (MIT), each with its licence beside it.
libesedb and dissect.esedb were only run to write the expected values, never included.
