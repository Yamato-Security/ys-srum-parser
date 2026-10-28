//! `SruDbIdMapTable`: what each `AppId` and `UserId` stands for. A row's
//! `IdBlob` is a binary SID when its `IdType` is 3, else UTF-16LE text: a
//! program's path, a service name, a packaged app's id, or (type 4) an
//! object the newer providers measure (a volume, a network adapter, `Total`).

use std::collections::HashMap;

use ese::{Database, Value};

use crate::time::Time;

const TABLE: &str = "SruDbIdMapTable";

/// What an id in `SruDbIdMapTable` names (its `IdType`; SrumECmd's
/// `MapType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdKind {
    /// 0: a program, by path (`\Device\HarddiskVolume2\…\a.exe`) or as
    /// `!!name!date!…` for one SRUM saw before its path.
    Application,
    /// 1: a service, by name.
    Service,
    /// 2: a packaged (Store) app, by its id.
    PackagedApp,
    /// 3: an account, by SID.
    Sid,
    /// 4: an object the newer providers measure: a volume, a network
    /// adapter, `Total`.
    Object,
    /// Any other `IdType`.
    Other(i64),
}

impl IdKind {
    fn of(id_type: i64) -> Self {
        match id_type {
            0 => Self::Application,
            1 => Self::Service,
            2 => Self::PackagedApp,
            3 => Self::Sid,
            4 => Self::Object,
            other => Self::Other(other),
        }
    }

    /// SrumECmd's name of the kind: `NormalApp`, `Service`, `ModernApp`,
    /// `Sid`, `Object`.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::Application => "NormalApp".into(),
            Self::Service => "Service".into(),
            Self::PackagedApp => "ModernApp".into(),
            Self::Sid => "Sid".into(),
            Self::Object => "Object".into(),
            Self::Other(id_type) => format!("IdType{id_type}"),
        }
    }
}

/// An id of `SruDbIdMapTable`.
#[derive(Debug, Clone, PartialEq)]
pub struct Id {
    /// `IdIndex`: the number `AppId` and `UserId` refer to.
    pub index: i64,
    /// `IdType`.
    pub kind: IdKind,
    /// `IdBlob` as text: the SID for [`IdKind::Sid`], else the name as
    /// written. `None` when the blob is blank or unreadable.
    pub name: Option<String>,
}

/// A program's name, with the `!!name!yyyy/MM/dd:HH:mm:ss!x!description`
/// form some ids have split up (as SrumECmd does).
#[derive(Debug, Clone, PartialEq)]
pub struct AppName {
    /// The path or name (`ExeInfo`).
    pub name: String,
    /// The description after the last `!` (`ExeInfoDescription`).
    pub description: Option<String>,
    /// The time in the `!!` form (`ExeTimestamp`), UTC.
    pub time: Option<Time>,
    /// The field between the time and the description.
    pub unknown: Option<String>,
}

impl AppName {
    /// `text`, split up when it has the `!!` form: a name (which may itself
    /// contain `!`), a time, an unknown field and a description. (SrumECmd
    /// adds a `!` for every empty field of a name, so it reads a name `!`
    /// as `!!`; here the fields are joined back as they were split.)
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let plain = || Self {
            name: text.to_owned(),
            description: None,
            time: None,
            unknown: None,
        };
        let Some(rest) = text.strip_prefix("!!") else {
            return plain();
        };
        let fields: Vec<&str> = rest.split('!').collect();
        if fields.len() < 4 {
            return plain();
        }
        let tail = fields.len() - 3;
        // the name is every field before the last three: a name with `!` in
        // it was split there too
        let name = fields[..tail].join("!");
        Self {
            name,
            time: parse_time(fields[tail]),
            unknown: Some(fields[tail + 1].to_owned()),
            description: Some(fields[tail + 2].to_owned()),
        }
    }
}

/// `yyyy/MM/dd:HH:mm:ss`, UTC.
fn parse_time(text: &str) -> Option<Time> {
    let (date, time) = text.split_once(':')?;
    let mut date = date.split('/');
    let mut time = time.split(':');
    let next = |part: &mut dyn Iterator<Item = &str>, digits: usize| -> Option<i64> {
        let field = part.next()?;
        (field.len() == digits && field.bytes().all(|b| b.is_ascii_digit()))
            .then(|| field.parse().ok())?
    };
    let (year, month, day) = (
        next(&mut date, 4)?,
        next(&mut date, 2)?,
        next(&mut date, 2)?,
    );
    let (hour, minute, second) = (
        next(&mut time, 2)?,
        next(&mut time, 2)?,
        next(&mut time, 2)?,
    );
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    // through the FILETIME epoch, so out of range values give None
    Time::from_filetime((seconds + 11_644_473_600).checked_mul(10_000_000)?)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Ids by their index.
pub(crate) struct IdMap(HashMap<i64, Id>);

impl IdMap {
    /// Read the map; rows that can't be read go to `problems`. Without the
    /// table, the map is empty (and that is a problem): the rest of the
    /// database is still read, with ids left unresolved.
    pub(crate) fn read(db: &Database<'_>, problems: &mut Vec<String>) -> Self {
        let (Some(table), Ok(mut rows)) = (db.table(TABLE), db.rows(TABLE)) else {
            problems.push(format!("no {TABLE}: ids are not resolved"));
            return Self(HashMap::new());
        };
        let mut ids = HashMap::new();
        for row in &mut rows {
            let get = |name: &str| row.get(table, name);
            let (Some(id_type), Some(index)) = (
                get("IdType").and_then(Value::as_i64),
                get("IdIndex").and_then(Value::as_i64),
            ) else {
                continue;
            };
            let kind = IdKind::of(id_type);
            // Some ids are blank (a NULL or empty blob): they name nothing.
            let name = match get("IdBlob").filter(|blob| !is_blank(blob)) {
                Some(blob) => {
                    let name = name(kind, blob);
                    if name.is_none() {
                        problems.push(format!("{TABLE}: id {index} doesn't read as a name"));
                    }
                    name
                }
                None => None,
            };
            ids.insert(index, Id { index, kind, name });
        }
        problems.extend(rows.problems().iter().map(|p| format!("{TABLE}: {p}")));
        Self(ids)
    }

    /// The id `index`.
    pub(crate) fn get(&self, index: i64) -> Option<&Id> {
        self.0.get(&index)
    }

    /// Every id, by index.
    pub(crate) fn into_sorted(self) -> Vec<Id> {
        let mut ids: Vec<Id> = self.0.into_values().collect();
        ids.sort_by_key(|id| id.index);
        ids
    }
}

/// NULL, or nothing but zeros.
fn is_blank(blob: &Value) -> bool {
    match blob {
        Value::Null => true,
        Value::Binary(bytes) => bytes.iter().all(|&b| b == 0),
        Value::Text(text) => text.is_empty(),
        _ => false,
    }
}

/// An `IdBlob` as a name: a SID, or text.
fn name(kind: IdKind, blob: &Value) -> Option<String> {
    match blob {
        Value::Text(text) => Some(text.clone()),
        Value::Binary(bytes) if kind == IdKind::Sid => sid(bytes),
        Value::Binary(bytes) => utf16(bytes),
        _ => None,
    }
}

/// UTF-16LE text, up to its first NUL.
fn utf16(bytes: &[u8]) -> Option<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&unit| unit != 0)
        .collect();
    (!units.is_empty()).then(|| String::from_utf16_lossy(&units))
}

/// A binary SID as text: revision, sub-authority count, a 48-bit
/// big-endian authority, then little-endian 32-bit sub-authorities.
fn sid(bytes: &[u8]) -> Option<String> {
    let (&revision, rest) = bytes.split_first()?;
    let (&count, rest) = rest.split_first()?;
    let authority = rest.get(..6)?;
    let subs = rest.get(6..6 + usize::from(count) * 4)?;
    let authority = authority
        .iter()
        .fold(0u64, |value, &byte| value << 8 | u64::from(byte));
    let subs = subs
        .chunks_exact(4)
        .map(|sub| format!("-{}", u32::from_le_bytes([sub[0], sub[1], sub[2], sub[3]])));
    Some(format!("S-{revision}-{authority}") + &subs.collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sids_and_names() {
        let local_system = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(sid(&local_system).as_deref(), Some("S-1-5-18"));
        assert_eq!(sid(&local_system[..10]), None);
        let name: Vec<u8> = "DiagTrack\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(utf16(&name).as_deref(), Some("DiagTrack"));
        assert_eq!(utf16(&[0, 0]), None);
    }

    #[test]
    fn app_names_in_the_bang_form() {
        let app = AppName::parse("!!svchost.exe!2026/01/02:03:04:05!0!Host Process");
        assert_eq!(app.name, "svchost.exe");
        assert_eq!(
            app.time.map(Time::to_iso8601).as_deref(),
            Some("2026-01-02T03:04:05.0000000Z")
        );
        assert_eq!(app.unknown.as_deref(), Some("0"));
        assert_eq!(app.description.as_deref(), Some("Host Process"));
        // a name with `!` in it, and one that is `!` itself
        assert_eq!(
            AppName::parse("!!a!b.exe!2015/05/01:18:16:33!d7253!").name,
            "a!b.exe"
        );
        assert_eq!(AppName::parse("!!!!2015/05/01:18:16:33!x!y").name, "!");
        // a bad time, and text that is not the form
        assert_eq!(AppName::parse("!!x.exe!2015/13/01:18:16:33!0!").time, None);
        let plain = AppName::parse(r"\Device\HarddiskVolume2\Windows\a.exe");
        assert_eq!(plain.name, r"\Device\HarddiskVolume2\Windows\a.exe");
        assert_eq!((plain.time, plain.description), (None, None));
    }
}
