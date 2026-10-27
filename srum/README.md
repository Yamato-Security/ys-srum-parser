# srum

Windows' System Resource Usage Monitor (`Windows\System32\sru\SRUDB.dat`), for forensics: what each program did, hour by hour, for about a month. Bytes it sent and received on which network, CPU time and disk bytes in the foreground and background, network connections. Evidence of exfiltration and of programs that ran, kept after they were deleted. Read with [`sootmark-ese`](https://crates.io/crates/sootmark-ese), a reader of ESE databases written from the format; no other dependency but its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-srum = "0.1"
```

```rust
let srum = srum::read(&std::fs::read("SRUDB.dat")?)?;
for entry in srum.entries.iter().filter(|e| e.kind == Some(srum::Kind::NetworkUsage)) {
    println!("{:?} {:?} {:?} sent {:?}", entry.time, entry.app, entry.user, entry.value("BytesSent"));
}
```

## What you get

- `read(bytes)`: every row of every provider table (one with `AutoIncId`, `TimeStamp`, `AppId` and `UserId`), table by table, as an `Entry`:
  - `time`: `TimeStamp`, when the figures were recorded (UTC);
  - `app` and `user`: `AppId` and `UserId` resolved through `SruDbIdMapTable`, to a program (a path such as `\Device\HarddiskVolume2\Windows\System32\svchost.exe`, a service name, a packaged app's id) and a SID (`S-1-5-18`); the raw ids are kept, and an id the map lacks stays unnamed;
  - `kind`: the provider, for the tables this crate knows: network usage (`BytesSent`, `BytesRecvd`, `InterfaceLuid`, `L2ProfileId`), application usage (cycle times, context switches, bytes read and written, foreground and background), network connectivity (`ConnectedTime`, `ConnectStartTime`), push notifications, energy usage, the application timeline, the VFU provider. A table it doesn't know is still read, unnamed;
  - `values`: the table's other columns, by name, as ESE values;
  - `times()`: the columns that hold a FILETIME rather than a number (`ConnectStartTime`, `EventTimestamp`, `EndTime`), read as UTC times.
- Damage goes to `problems`, never a panic; only a file that isn't an ESE database, or has no `SruDbIdMapTable`, is an error.

Not read here: the transaction logs (`SRU*.log`), whose changes a dirty database may lack (`sootmark-ese` reports a dirty shutdown); the registry's SRUM extension keys.

## How it's checked

- plaso's `SRUDB.dat` (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): the entries plaso's own SRUM tests expect, 18,283 across the three providers plaso reads, and the values it checks (programs, SIDs, bytes, interface, recorded and connection times, to the 100 ns). `sootmark-ese` matches libesedb on every value of this database.
- Property tests: arbitrary bytes and the database damaged anywhere give entries, problems or an error, never a panic.

## Licence

MIT or Apache-2.0, at your option. The test database under `tests/fixtures/plaso/` keeps plaso's licence (Apache-2.0).
