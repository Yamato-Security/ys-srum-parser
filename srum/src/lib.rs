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
//!         entry.app,
//!         entry.user,
//!         entry.value("BytesSent")
//!     );
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Damage is reported in `problems`, never a panic; a table this crate
//! doesn't know is still read, its columns kept as they are.

mod id_map;

use common::time::Ts;
use ese::{Database, Value};

use id_map::IdMap;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The columns every provider table has, read into an [`Entry`]'s fields.
const COMMON_COLUMNS: [&str; 4] = ["AutoIncId", "TimeStamp", "AppId", "UserId"];

/// A provider this crate knows, by its table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl Kind {
    const TABLES: [(&'static str, Self); 8] = [
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
    ];

    /// The provider whose table this is (GUID case ignored).
    #[must_use]
    pub fn of_table(name: &str) -> Option<Self> {
        Self::TABLES
            .iter()
            .find(|(table, _)| table.eq_ignore_ascii_case(name))
            .map(|&(_, kind)| kind)
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
        }
    }

    /// The columns of this provider that hold a FILETIME rather than a
    /// number: `ConnectStartTime`, `EventTimestamp`, `EndTime`.
    const fn time_columns(self) -> &'static [&'static str] {
        match self {
            Self::NetworkConnectivity => &["ConnectStartTime"],
            Self::EnergyUsage => &["EventTimestamp"],
            Self::ApplicationTimeline => &["EndTime"],
            _ => &[],
        }
    }
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
    /// `TimeStamp`: when the figures were recorded (UTC, to the minute).
    pub time: Option<Ts>,
    /// `AppId`, as written.
    pub app_id: Option<i64>,
    /// The program `AppId` names: a path (`\Device\HarddiskVolume2\…`), a
    /// service name or a packaged app's id; `None` when the map lacks it.
    pub app: Option<String>,
    /// `UserId`, as written.
    pub user_id: Option<i64>,
    /// The account `UserId` names, as a SID (`S-1-5-18`).
    pub user: Option<String>,
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

    /// The columns that hold times besides `TimeStamp`, read as UTC FILETIMEs
    /// (`ConnectStartTime`: when the connection began), with their names.
    #[must_use]
    pub fn times(&self) -> Vec<(&'static str, Ts)> {
        let columns = self.kind.map_or(&[][..], Kind::time_columns);
        columns
            .iter()
            .filter_map(|&column| {
                let ticks = self.value(column)?.as_i64()?;
                Some((column, Ts::from_filetime(u64::try_from(ticks).ok()?)))
            })
            .collect()
    }
}

/// A SRUM database's entries.
#[derive(Debug, Clone, PartialEq)]
pub struct Srum {
    /// Every provider table's rows, table by table.
    pub entries: Vec<Entry>,
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
/// When it isn't an ESE database, or has no `SruDbIdMapTable`.
pub fn read(data: &[u8]) -> Result<Srum, Error> {
    let db = Database::open(data).map_err(|e| Error(e.to_string()))?;
    let mut problems = db.problems.clone();
    let ids = IdMap::read(&db, &mut problems)?;
    let mut entries = Vec::new();
    for table in db.tables.iter().filter(|t| is_provider(t)) {
        let Ok(mut rows) = db.rows(&table.name) else {
            continue;
        };
        for row in &mut rows {
            entries.push(entry(table, &row.values, &ids));
        }
        problems.extend(
            rows.problems()
                .iter()
                .map(|p| format!("{}: {p}", table.name)),
        );
    }
    Ok(Srum { entries, problems })
}

/// A provider table: one with the common columns.
fn is_provider(table: &ese::Table) -> bool {
    COMMON_COLUMNS
        .iter()
        .all(|column| table.column_index(column).is_some())
}

fn entry(table: &ese::Table, values: &[Value], ids: &IdMap) -> Entry {
    let get = |name: &str| table.column_index(name).and_then(|at| values.get(at));
    let integer = |name: &str| get(name).and_then(Value::as_i64);
    let app_id = integer("AppId");
    let user_id = integer("UserId");
    Entry {
        table: table.name.clone(),
        kind: Kind::of_table(&table.name),
        id: integer("AutoIncId"),
        time: get("TimeStamp")
            .and_then(Value::as_f64)
            .map(Ts::from_ole_date),
        app_id,
        app: app_id.and_then(|id| ids.name(id)),
        user_id,
        user: user_id.and_then(|id| ids.name(id)),
        values: table
            .columns
            .iter()
            .zip(values)
            .filter(|(column, _)| !COMMON_COLUMNS.contains(&column.name.as_str()))
            .map(|(column, value)| (column.name.clone(), value.clone()))
            .collect(),
    }
}
