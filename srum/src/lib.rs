//! Windows' System Resource Usage Monitor (SRUM,
//! `Windows\System32\sru\SRUDB.dat`): what each program did, hour by hour,
//! for about a month: bytes it sent and received on which network, CPU
//! time and disk bytes in the foreground and background, network
//! connections. Evidence of exfiltration and of programs that ran, kept
//! even after they were deleted.
//!
//! The database is an ESE file, read with `sootmark-ese`. Each provider
//! writes a table named after its GUID; every row has an `AutoIncId`, a
//! `TimeStamp` (when the hour's figures were recorded, UTC), and an `AppId`
//! and `UserId` that `SruDbIdMapTable` resolves to a program (a path, a
//! service name or a packaged app's id) and an account's SID.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let srum = srum::read(&std::fs::read("SRUDB.dat")?)?;
//! for entry in srum.entries.iter().filter(|e| e.kind == Some(srum::Kind::NetworkUsage)) {
//!     println!(
//!         "{:?} {:?} {:?} sent {:?}",
//!         entry.time,
//!         entry.app.as_ref().map(|app| &app.name),
//!         entry.user,
//!         entry.value("BytesSent")
//!     );
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Damage is reported in `problems`, never a panic; a table this crate
//! doesn't know is still read, its columns kept as they are. Values are
//! kept as the database has them: a NULL stays [`Value::Null`], not 0.
//!
//! The volume's `SOFTWARE` hive names what the database only numbers: the
//! accounts (`ProfileList`) and the wireless networks (`WlanSvc` profiles).
//! Read it with any registry parser into a [`Context`] and pass it to
//! [`read_with`].

mod id_map;
mod interface;
mod time;

use std::collections::HashMap;

use ese::Database;
pub use ese::Value;

pub use id_map::{AppName, Id, IdKind};
pub use interface::{interface_type, interface_type_name};
pub use time::Time;

use id_map::IdMap;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The columns every provider table has, read into an [`Entry`]'s fields.
const COMMON_COLUMNS: [&str; 4] = ["AutoIncId", "TimeStamp", "AppId", "UserId"];

/// A provider this crate knows, by its table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `{973F5D5C-1D90-4944-BE8E-24B94231A174}`: bytes sent and received,
    /// per program and network interface.
    NetworkUsage,
    /// `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}`: CPU cycles, context
    /// switches and disk activity, foreground and background, per program.
    ApplicationUsage,
    /// `{DD6636C4-8929-4683-974E-22C046A43763}`: how long each network
    /// interface was connected, and since when.
    NetworkConnectivity,
    /// `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}`: push notifications.
    PushNotifications,
    /// `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}`: battery and energy.
    EnergyUsage,
    /// `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT`: the same, long-term.
    EnergyUsageLongTerm,
    /// `{5C8CF1C7-7257-4F13-B223-970EF5939312}`: per-program timelines of
    /// focus, input, audio, CPU, disk and network.
    ApplicationTimeline,
    /// `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}`: the VFU provider.
    VfuProvider,
    /// `{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}`: the energy estimation
    /// provider (one binary column).
    EnergyEstimation,
    /// `{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}`: the tagged energy provider.
    TaggedEnergy,
    /// `{DC3D3B50-BB90-5066-FA4E-A5F90DD8B677}` (Windows Server): processor
    /// time per program.
    ProcessorTime,
    /// `{841A7317-3805-518B-C2EA-AD224CB4AF84}` (Windows Server): sizes in
    /// bytes, per object (a volume).
    SizeInBytes,
    /// `{17F4D97B-F26A-5E79-3A82-90040A47D13D}` (Windows Server): total and
    /// used, per object (a volume).
    TotalUsed,
    /// `{EEE2F477-0659-5C47-EF03-6D6BEFD441B3}` (Windows Server): bytes in
    /// and out, per object (a network adapter).
    NetworkBytes,
}

impl Kind {
    const TABLES: [(&'static str, Self); 14] = [
        ("{973F5D5C-1D90-4944-BE8E-24B94231A174}", Self::NetworkUsage),
        (
            "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
            Self::ApplicationUsage,
        ),
        (
            "{DD6636C4-8929-4683-974E-22C046A43763}",
            Self::NetworkConnectivity,
        ),
        (
            "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}",
            Self::PushNotifications,
        ),
        ("{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}", Self::EnergyUsage),
        (
            "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT",
            Self::EnergyUsageLongTerm,
        ),
        (
            "{5C8CF1C7-7257-4F13-B223-970EF5939312}",
            Self::ApplicationTimeline,
        ),
        ("{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}", Self::VfuProvider),
        (
            "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}",
            Self::EnergyEstimation,
        ),
        ("{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}", Self::TaggedEnergy),
        (
            "{DC3D3B50-BB90-5066-FA4E-A5F90DD8B677}",
            Self::ProcessorTime,
        ),
        ("{841A7317-3805-518B-C2EA-AD224CB4AF84}", Self::SizeInBytes),
        ("{17F4D97B-F26A-5E79-3A82-90040A47D13D}", Self::TotalUsed),
        ("{EEE2F477-0659-5C47-EF03-6D6BEFD441B3}", Self::NetworkBytes),
    ];

    /// Every provider this crate knows.
    pub fn all() -> impl Iterator<Item = Self> {
        Self::TABLES.iter().map(|&(_, kind)| kind)
    }

    /// The provider whose table this is (GUID case ignored).
    #[must_use]
    pub fn of_table(name: &str) -> Option<Self> {
        Self::TABLES
            .iter()
            .find(|(table, _)| table.eq_ignore_ascii_case(name))
            .map(|&(_, kind)| kind)
    }

    /// The provider's table.
    #[must_use]
    pub fn table(self) -> &'static str {
        Self::TABLES
            .iter()
            .find(|&&(_, kind)| kind == self)
            .map_or("", |&(table, _)| table)
    }

    /// A short name: `network usage`, `application usage`, ….
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NetworkUsage => "network usage",
            Self::ApplicationUsage => "application usage",
            Self::NetworkConnectivity => "network connectivity",
            Self::PushNotifications => "push notifications",
            Self::EnergyUsage => "energy usage",
            Self::EnergyUsageLongTerm => "energy usage (long term)",
            Self::ApplicationTimeline => "application timeline",
            Self::VfuProvider => "VFU provider",
            Self::EnergyEstimation => "energy estimation",
            Self::TaggedEnergy => "tagged energy",
            Self::ProcessorTime => "processor time",
            Self::SizeInBytes => "size in bytes",
            Self::TotalUsed => "total and used",
            Self::NetworkBytes => "network bytes",
        }
    }

    /// The name SrumECmd gives the provider's output
    /// (`<time>_SrumECmd_<name>_Output.csv`); the two energy usage tables
    /// share `EnergyUsage`.
    #[must_use]
    pub const fn output_name(self) -> &'static str {
        match self {
            Self::NetworkUsage => "NetworkUsages",
            Self::ApplicationUsage => "AppResourceUseInfo",
            Self::NetworkConnectivity => "NetworkConnections",
            Self::PushNotifications => "PushNotifications",
            Self::EnergyUsage | Self::EnergyUsageLongTerm => "EnergyUsage",
            Self::ApplicationTimeline => "AppTimelineProvider",
            Self::VfuProvider => "vfuprov",
            Self::EnergyEstimation => "EnergyEstimation",
            Self::TaggedEnergy => "TaggedEnergy",
            Self::ProcessorTime => "ProcessorTime",
            Self::SizeInBytes => "SizeInBytes",
            Self::TotalUsed => "TotalUsed",
            Self::NetworkBytes => "NetworkBytes",
        }
    }

    /// The columns of this provider that hold a FILETIME rather than a
    /// number.
    #[must_use]
    pub const fn time_columns(self) -> &'static [&'static str] {
        match self {
            Self::NetworkConnectivity => &["ConnectStartTime"],
            Self::EnergyUsage | Self::EnergyUsageLongTerm => &["EventTimestamp"],
            Self::ApplicationTimeline => &["EndTime"],
            Self::VfuProvider => &["StartTime", "EndTime"],
            _ => &[],
        }
    }
}

/// What the volume's `SOFTWARE` hive says about the ids the database only
/// numbers. Empty by default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Context {
    /// Account names by SID: the last component of each `ProfileImagePath`
    /// under `Microsoft\Windows NT\CurrentVersion\ProfileList`.
    pub user_names: HashMap<String, String>,
    /// Wireless network names by profile index: each
    /// `Microsoft\WlanSvc\Interfaces\*\Profiles\*` key's `ProfileIndex`, and
    /// the SSID in its `MetaData\Channel Hints`.
    pub network_profiles: HashMap<i64, String>,
}

/// One row of a provider table.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// The table it's in (a GUID, with `LT` for long-term tables).
    pub table: String,
    /// The provider, when this crate knows the table.
    pub kind: Option<Kind>,
    /// `AutoIncId`.
    pub id: Option<i64>,
    /// `TimeStamp`: when the figures were recorded (UTC, rounded to the
    /// millisecond as SrumECmd does).
    pub time: Option<Time>,
    /// `AppId`, as written.
    pub app_id: Option<i64>,
    /// What `AppId` names, when the map has it: a program, a service, a
    /// packaged app or an object, with its name split up when it has the
    /// `!!` form.
    pub app: Option<AppName>,
    /// The kind of id `AppId` is.
    pub app_kind: Option<IdKind>,
    /// `UserId`, as written.
    pub user_id: Option<i64>,
    /// The account `UserId` names, as a SID (`S-1-5-18`).
    pub user: Option<String>,
    /// The account's name, from the [`Context`].
    pub user_name: Option<String>,
    /// The wireless network `L2ProfileId` names (the network tables), from
    /// the [`Context`].
    pub profile_name: Option<String>,
    /// The table's other columns, by name, in table order.
    pub values: Vec<(String, Value)>,
}

impl Entry {
    /// The value of column `name`, among [`Entry::values`].
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&Value> {
        self.values
            .iter()
            .find(|(column, _)| column == name)
            .map(|(_, value)| value)
    }

    /// The columns that hold times besides `TimeStamp`, read as UTC
    /// FILETIMEs, with their names (`ConnectStartTime`: when the connection
    /// began): `None` for a value that is not a time (0, negative, the
    /// maximum); a NULL or absent column is left out.
    #[must_use]
    pub fn times(&self) -> Vec<(&'static str, Option<Time>)> {
        let columns = self.kind.map_or(&[][..], Kind::time_columns);
        columns
            .iter()
            .filter_map(|&column| {
                let ticks = self.value(column)?.as_i64()?;
                Some((column, Time::from_filetime(ticks)))
            })
            .collect()
    }

    /// The type of the network interface `InterfaceLuid` names (its IANA
    /// ifType), for the network tables.
    #[must_use]
    pub fn interface_type(&self) -> Option<u16> {
        self.value("InterfaceLuid")
            .and_then(Value::as_i64)
            .map(interface_type)
    }
}

/// A table of the database and how it read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableInfo {
    /// Its name.
    pub name: String,
    /// The provider, when this crate knows the table.
    pub kind: Option<Kind>,
    /// Whether it has the provider columns (and so gave entries).
    pub provider: bool,
    /// The rows read.
    pub rows: usize,
}

/// A SRUM database's entries.
#[derive(Debug, Clone, PartialEq)]
pub struct Srum {
    /// Every provider table's rows, table by table.
    pub entries: Vec<Entry>,
    /// `SruDbIdMapTable`, by index.
    pub ids: Vec<Id>,
    /// Every table of the database, with how many rows it gave.
    pub tables: Vec<TableInfo>,
    /// Whether the database was not shut down cleanly: changes still only in
    /// the transaction logs (`SRU*.log`) are missing.
    pub dirty: bool,
    /// Damage in the database, and ids the map doesn't resolve.
    pub problems: Vec<String>,
}

/// Why a file can't be read as SRUM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Read a SRUM database (`SRUDB.dat`).
///
/// # Errors
/// When it isn't an ESE database.
pub fn read(data: &[u8]) -> Result<Srum, Error> {
    read_with(data, &Context::default())
}

/// Read a SRUM database (`SRUDB.dat`), naming accounts and wireless
/// networks with `context` (from the volume's `SOFTWARE` hive).
///
/// # Errors
/// When it isn't an ESE database.
pub fn read_with(data: &[u8], context: &Context) -> Result<Srum, Error> {
    let db = Database::open(data).map_err(|e| Error(e.to_string()))?;
    let mut problems = db.problems.clone();
    let ids = IdMap::read(&db, &mut problems);
    let mut entries = Vec::new();
    let mut tables = Vec::new();
    let mut unresolved = 0usize;
    for table in &db.tables {
        let provider = is_provider(table);
        let mut info = TableInfo {
            name: table.name.clone(),
            kind: Kind::of_table(&table.name),
            provider,
            rows: 0,
        };
        let mut rows = match db.rows(&table.name) {
            Ok(rows) => rows,
            Err(error) => {
                problems.push(format!("{}: {error}", table.name));
                tables.push(info);
                continue;
            }
        };
        for row in &mut rows {
            info.rows += 1;
            if provider {
                let entry = entry(table, &row.values, &ids, context);
                unresolved += usize::from(entry.app_id.is_some() && entry.app.is_none())
                    + usize::from(entry.user_id.is_some() && entry.user.is_none());
                entries.push(entry);
            }
        }
        problems.extend(
            rows.problems()
                .iter()
                .map(|p| format!("{}: {p}", table.name)),
        );
        tables.push(info);
    }
    if unresolved > 0 {
        problems.push(format!(
            "{unresolved} AppId / UserId values are not in SruDbIdMapTable"
        ));
    }
    Ok(Srum {
        entries,
        ids: ids.into_sorted(),
        tables,
        dirty: db.header.state == ese::DatabaseState::DirtyShutdown,
        problems,
    })
}

/// A provider table: one with the common columns.
fn is_provider(table: &ese::Table) -> bool {
    COMMON_COLUMNS
        .iter()
        .all(|column| table.column_index(column).is_some())
}

fn entry(table: &ese::Table, values: &[Value], ids: &IdMap, context: &Context) -> Entry {
    let get = |name: &str| table.column_index(name).and_then(|at| values.get(at));
    let integer = |name: &str| get(name).and_then(Value::as_i64);
    let app_id = integer("AppId");
    let user_id = integer("UserId");
    let app_entry = app_id.and_then(|id| ids.get(id));
    // An account is a SID; a UserId naming anything else is left unresolved.
    let user = user_id
        .and_then(|id| ids.get(id))
        .filter(|id| id.kind == IdKind::Sid)
        .and_then(|id| id.name.clone());
    Entry {
        table: table.name.clone(),
        kind: Kind::of_table(&table.name),
        id: integer("AutoIncId"),
        time: get("TimeStamp")
            .and_then(Value::as_f64)
            .and_then(Time::from_ole_date),
        app_id,
        app: app_entry
            .and_then(|id| id.name.as_deref())
            .map(AppName::parse),
        app_kind: app_entry.map(|id| id.kind),
        user_id,
        user_name: user
            .as_ref()
            .and_then(|sid| context.user_names.get(sid).cloned()),
        user,
        profile_name: integer("L2ProfileId")
            .and_then(|id| context.network_profiles.get(&id).cloned()),
        values: table
            .columns
            .iter()
            .zip(values)
            .filter(|(column, _)| !COMMON_COLUMNS.contains(&column.name.as_str()))
            .map(|(column, value)| (column.name.clone(), value.clone()))
            .collect(),
    }
}
