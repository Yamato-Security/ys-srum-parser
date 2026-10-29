# srum

Windows' System Resource Usage Monitor (`Windows\System32\sru\SRUDB.dat`), for forensics: what each program did, hour by hour, for about a month. Bytes it sent and received on which network, CPU time and disk bytes in the foreground and background, network connections, energy, the application timeline. Evidence of exfiltration and of programs that ran, kept after they were deleted. Read with [`ys-srum-parser-ese`](../ese), a reader of ESE databases written from the format; no other dependency.

Part of [ys-srum-parser](https://github.com/Yamato-Security/ys-srum-parser), Yamato Security's fork of Sootmark's [srum](https://github.com/Sootmark/srum).

```toml
[dependencies]
srum = { package = "ys-srum-parser", git = "https://github.com/Yamato-Security/ys-srum-parser", rev = "<commit>" }
```

```rust
let srum = srum::read(&std::fs::read("SRUDB.dat")?)?;
for entry in srum.entries.iter().filter(|e| e.kind == Some(srum::Kind::NetworkUsage)) {
    println!(
        "{:?} {:?} {:?} sent {:?}",
        entry.time,
        entry.app.as_ref().map(|app| &app.name),
        entry.user,
        entry.value("BytesSent")
    );
}
```

## What you get

- `read(bytes)`: every row of every provider table (one with `AutoIncId`, `TimeStamp`, `AppId` and `UserId`), table by table, as an `Entry`:
  - `time`: `TimeStamp`, when the figures were recorded (UTC), an OLE date rounded to the millisecond, as .NET's `DateTime.FromOADate` rounds it;
  - `app` and `app_kind`: `AppId` resolved through `SruDbIdMapTable` to a program's path (`\Device\HarddiskVolume2\Windows\System32\svchost.exe`), a service, a packaged app or (Windows Server) an object such as a volume, with `!!name!yyyy/MM/dd:HH:mm:ss!x!description` names split into `AppName`'s name, time and description;
  - `user`: `UserId` resolved to a SID (`S-1-5-18`); an id naming anything but an account stays unresolved. The raw ids are kept (`app_id`, `user_id`);
  - `kind`: the provider, for the 14 tables this crate knows: network usage, application resource usage, network connectivity, push notifications, energy usage (and its long-term table), the application timeline, the VFU provider, energy estimation, tagged energy, and Windows Server's processor time, size in bytes, total and used, and network bytes. `Kind::output_name` is a name for the table's output (`NetworkUsages`, `AppResourceUseInfo`, …). A table it doesn't know is still read, unnamed;
  - `values`: the table's other columns, by name, as ESE values; a NULL stays `Value::Null`, not 0;
  - `times()`: the columns that hold a FILETIME rather than a number (`ConnectStartTime`, `EventTimestamp`, the timeline's `EndTime`, the VFU provider's `StartTime` and `EndTime`), as UTC times;
  - `interface_type()`: the IANA interface type `InterfaceLuid` holds in its top 16 bits (`interface_type_name`: `IF_TYPE_ETHERNET_CSMACD`, `IF_TYPE_IEEE80211`, …).
- `read_with(bytes, &context)`: the same, with the names the volume's `SOFTWARE` hive gives what the database only numbers: `user_name` from `ProfileList`, and `profile_name`, the wireless network an `L2ProfileId` stands for, from the `WlanSvc` profiles. Read the hive with any registry parser into a `Context`.
- `read_with_options(bytes, &context, &options)`: the same, with each entry's `cells` when `Options::value_states` asks for them: how each column's value was read (`ValueState`: parsed, NULL in the database, a type with no decoding, stored but damaged), so a NULL can be told from a value that couldn't be read; `Entry::state(name)` gives `Absent` for a column the table hasn't. `Options::raw_values` keeps the bytes each value was read from too (`Entry::raw`; none for a NULL, nothing made up).
- `ids`: `SruDbIdMapTable` itself, with each id's type; `tables`: every table of the database and the rows it gave; `dirty`: the database was not shut down cleanly.
- Damage goes to `problems`, never a panic: damaged pages and records, a missing or damaged `SruDbIdMapTable` (the rest is still read, ids unresolved), ids the map lacks. Only a file that isn't an ESE database is an error.

Not read here: the transaction logs (`SRU*.log`), whose changes a dirty database may lack (`dirty` says so); the registry's SRUM extension keys.

## How it's checked

- Three real databases of [DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum) (MIT, `tests/fixtures/museum/`): Windows 11 left dirty, Windows 10, and Windows Server 2022 with its own tables. Every one of their 2,939 entries is compared with a decoding written independently from [dissect.esedb](https://github.com/fox-it/dissect.esedb)'s values: time, program, account and FILETIME columns.
- plaso's `SRUDB.dat` (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): the entries plaso's own SRUM tests expect, 18,283 across the three providers plaso reads, and the values it checks (programs, SIDs, bytes, interface, recorded and connection times, to the 100 ns).
- Property tests: arbitrary bytes and the database damaged anywhere give entries, problems or an error, never a panic.

## Licence

MIT or Apache-2.0, at your option. The test databases keep their licences: plaso's (Apache-2.0) under `tests/fixtures/plaso/`, DFIRArtifactMuseum's (MIT) under `tests/fixtures/museum/`.
