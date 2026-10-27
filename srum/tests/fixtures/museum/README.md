# DFIRArtifactMuseum SRUM databases

Three `SRUDB.dat` files of [DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum)
(MIT License, `Windows/SRUM/`), stored gzip-compressed (`gzip -9n`), otherwise unmodified:

| File | Source | SHA-256 of the uncompressed file |
| --- | --- | --- |
| `win11_rathbunvm_dirty.dat.gz` | `Win11/RathbunVM/Dirty/SRUDB.dat` (dirty shutdown) | b1b0e0e9e95cdc44bc4e9a9671cf0e3dc37cc3ab433c98f4ecbf482965c0f13a |
| `win10_rathbunvm.dat.gz` | `Win10/RathbunVM/Clean/SRUDB.dat` | f0ce646fee265c8c438459fc3bcb616e084c875389a6189d2945be4a52e1602c |
| `server2022_aptsimulatorvm.dat.gz` | `Server2022/APTSimulatorVM/APTSimulatorVM_SRUM_Clean_Server2022_1DayLater.7z` (`SRU/SRUDB.dat`) | eb683ffcea831e6e81e28df9c98f8d441b5143fa23c0092c1286c0b911370349 |

`*.dissect.tsv.gz` lists every provider entry (table, `AutoIncId`, `TimeStamp`, the name `AppId`
stands for, the SID `UserId` stands for, and the FILETIME columns) decoded independently from
[dissect.esedb](https://github.com/fox-it/dissect.esedb) 3.18's values: OLE dates rounded to the
millisecond like .NET's `DateTime.FromOADate`, `IdBlob` read as a SID (`IdType` 3) or UTF-16LE text.
dissect.esedb and libesedb agree on every value of these databases' tables. Tabs, newlines and
backslashes in names are escaped as `\t`, `\n` and `\\`.
