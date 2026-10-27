//! `SruDbIdMapTable`: what each `AppId` and `UserId` stands for. A row's
//! `IdBlob` is a binary SID when its `IdType` is 3, else a UTF-16LE name: a
//! program's path, a service name or a packaged app's id.

use std::collections::HashMap;

use ese::{Database, Value};

use crate::Error;

const TABLE: &str = "SruDbIdMapTable";
/// The `IdType` of an account.
const SID: i64 = 3;

/// Ids to the names they stand for.
pub(crate) struct IdMap(HashMap<i64, String>);

impl IdMap {
    /// Read the map; rows that can't be read go to `problems`.
    pub(crate) fn read(db: &Database<'_>, problems: &mut Vec<String>) -> Result<Self, Error> {
        let table = db
            .table(TABLE)
            .ok_or_else(|| Error(format!("no {TABLE}: not a SRUM database")))?;
        let mut rows = db.rows(TABLE).map_err(|e| Error(e.to_string()))?;
        let mut names = HashMap::new();
        for row in &mut rows {
            let get = |name: &str| row.get(table, name);
            let (Some(kind), Some(index)) = (
                get("IdType").and_then(Value::as_i64),
                get("IdIndex").and_then(Value::as_i64),
            ) else {
                continue;
            };
            // Some ids are blank (a NULL or empty blob): they name nothing.
            let Some(blob) = get("IdBlob").filter(|blob| !is_blank(blob)) else {
                continue;
            };
            match name(kind, blob) {
                Some(name) => {
                    names.insert(index, name);
                }
                None => problems.push(format!("{TABLE}: id {index} doesn't read as a name")),
            }
        }
        problems.extend(rows.problems().iter().map(|p| format!("{TABLE}: {p}")));
        Ok(Self(names))
    }

    /// The name `id` stands for.
    pub(crate) fn name(&self, id: i64) -> Option<String> {
        self.0.get(&id).cloned()
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
fn name(kind: i64, blob: &Value) -> Option<String> {
    match blob {
        Value::Text(text) => Some(text.clone()),
        Value::Binary(bytes) if kind == SID => sid(bytes),
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
}
