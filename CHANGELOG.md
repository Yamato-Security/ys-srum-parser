# Changelog

## 1.0.0 (Unreleased)

### Changed
- The crates are named after their repository: `ys-srum-parser` (was `sootmark-srum`; library
  `srum`) and `ys-srum-parser-ese` (was `sootmark-ese`; library `ese`), version 1.0.0, by Florian
  Amette and Zach Mathis (@yamatosecurity), on Rust's 2024 edition, and require Rust 1.99. Depend
  on them as `srum = { package = "ys-srum-parser", … }`. (@YamatoSecurity)

## 0.2.0 (ys-srum-parser)

First version of Yamato Security's fork, of both crates: sootmark-ese 0.1.1 (Sootmark/ese 3570ed9)
and sootmark-srum 0.1.0 (Sootmark/srum aa16800). (@YamatoSecurity)

### sootmark-ese

#### Added
- Column type 18 (`UnsignedLongLong`, Windows 10 and later), read as `Value::U64`; it was an
  unknown type read as binary.
- `Rows::long_value_limit` and `ROW_LONG_VALUE_LIMIT` (256 MiB): the most long value bytes one row
  reads; the long values after it are NULL, with a problem.

#### Fixed
- A damaged or crafted row whose tagged columns referred to one long value many times was given a
  copy of it per reference (a 2.6 KB row became 457 KB with 206 references).
- Xpress match lengths overflowed on 32-bit targets (a panic in debug builds); the additions saturate.

### sootmark-srum

#### Added
- Six more provider tables: energy estimation, tagged energy, and Windows Server 2022's processor
  time, size in bytes, total and used, and network bytes (`Kind`, 14 in all), and `Kind::all`,
  `Kind::table`, `Kind::time_columns` and `Kind::output_name`, SrumECmd's name for each table's
  output.
- More FILETIME columns read as times by `Entry::times`: the VFU provider's `StartTime` and
  `EndTime`, and the long-term energy table's `EventTimestamp`.
- `Srum::ids` (`SruDbIdMapTable` with each id's type, `IdKind`), `Entry::app_kind`, and `AppName`:
  `!!name!yyyy/MM/dd:HH:mm:ss!x!description` names split into a name, a time and a description, as
  SrumECmd splits them.
- `interface_type` and `interface_type_name`: the IANA interface type an `InterfaceLuid` holds
  (`Entry::interface_type`).
- `read_with` and `Context`: account names (`Entry::user_name`) and wireless network names
  (`Entry::profile_name`) from the volume's `SOFTWARE` hive, read by the caller.
- `Srum::dirty`, and `Srum::tables`: every table of the database and the rows it gave.
- `Time`, the crate's own UTC time (OLE dates and FILETIMEs, `to_iso8601`).
- Tests on three real databases (Windows 11 left dirty, Windows 10, Windows Server 2022;
  DFIRArtifactMuseum, MIT), every entry compared with a decoding written independently from
  dissect.esedb's values.

#### Changed
- `TimeStamp` is rounded to the millisecond, as SrumECmd (.NET's `DateTime.FromOADate`) rounds it.
- `Entry::app` is an `AppName`; a `UserId` resolves only to an id that is a SID.
- `Entry::times` gives `None` for a value that is not a time: 0 and the maximum (sootmark-common's
  not-set and sentinel times) and negative values (left out before).
- No dependency but `sootmark-ese`: sootmark-common's time type is replaced by `Time`.

#### Fixed
- A database without a readable `SruDbIdMapTable` was an error; it is now read, its ids unresolved
  and reported in `problems`.

### Both
- One workspace and one CI (Linux, macOS and Windows; MSRV 1.80; wasm32; cargo-deny) with the
  actions pinned by commit, replacing upstream's per-crate workflows and crates.io publishing.
- Not published (`publish = false`); versions from 0.2.0 are the fork's own.
