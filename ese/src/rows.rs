//! The rows of a table, read one at a time as the walk of its tree reaches
//! them, each record decoded into one value per column.

use std::borrow::Cow;

use crate::btree::{Cursor, Entry};
use crate::bytes::{u8_at, u16_at};
use crate::compression;
use crate::long_value::LongValues;
use crate::pager::Pages;
use crate::record::{Record, Tagged};
use crate::schema::{Column, ColumnKind, Table};
use crate::value::{self, Value, ValueState};

/// A multi-value offset with this bit set locates a long value identifier.
const SEPARATED_VALUE: u16 = 0x8000;
const MULTI_VALUE_OFFSET_MASK: u16 = 0x7fff;
/// Bytes of a multi-value offset.
const MULTI_VALUE_OFFSET_SIZE: usize = 2;

/// A row of a table.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// The leaf page holding its record.
    pub page: u32,
    /// One value per column, in the order of [`Table::columns`]: NULL when
    /// not set, or when it couldn't be read (the problems say why).
    pub values: Vec<Value>,
    /// How each value was read, in the same order: what a NULL stands for.
    pub states: Vec<ValueState>,
    /// The bytes each value was decoded from (a long value's whole data,
    /// decompressed), in the same order, `None` for a value with no bytes
    /// (NULL, or damage before any could be read). Empty unless
    /// [`Rows::keep_raw`].
    pub raw: Vec<Option<Vec<u8>>>,
}

impl Row {
    /// The value of the column named `name` of `table` (the table the row
    /// was read from).
    #[must_use]
    pub fn get<'r>(&'r self, table: &Table, name: &str) -> Option<&'r Value> {
        self.values.get(table.column_index(name)?)
    }

    /// How the value of the column named `name` of `table` was read;
    /// [`ValueState::Absent`] when the table has no such column.
    #[must_use]
    pub fn state(&self, table: &Table, name: &str) -> ValueState {
        table
            .column_index(name)
            .and_then(|at| self.states.get(at).copied())
            .unwrap_or(ValueState::Absent)
    }
}

/// A value, how it was read, and its bytes when they are kept.
type Cell = (Value, ValueState, Option<Vec<u8>>);

/// The rows of a table, in key order (the order of its primary index).
///
/// Damage met on the way (unreadable pages, damaged records, values that
/// don't decode, long values missing or cut short) is listed in
/// [`Rows::problems`]; the rest of the row and the rows after it still
/// read.
pub struct Rows<'a> {
    pages: &'a Pages<'a>,
    table: &'a Table,
    cursor: Cursor<'a>,
    /// The table's long value tree, read when the first long value is.
    long_values: Option<LongValues<'a>>,
    /// Long value bytes read for the current row.
    row_long_value_bytes: usize,
    /// The most long value bytes one row may read.
    long_value_limit: usize,
    /// Keep each value's bytes ([`Row::raw`]).
    keep_raw: bool,
}

/// The default of [`Rows::long_value_limit`]: 256 MiB.
pub const ROW_LONG_VALUE_LIMIT: usize = 256 * 1024 * 1024;

impl<'a> Rows<'a> {
    pub(crate) fn new(pages: &'a Pages<'a>, table: &'a Table) -> Self {
        Self {
            pages,
            table,
            cursor: Cursor::new(pages, table.root_page),
            long_values: None,
            row_long_value_bytes: 0,
            long_value_limit: ROW_LONG_VALUE_LIMIT,
            keep_raw: false,
        }
    }

    /// Keep the bytes each value was decoded from, in [`Row::raw`]: for
    /// checking a value against its source. Off by default: a row's values
    /// then take twice the memory.
    #[must_use]
    pub fn keep_raw(mut self, keep: bool) -> Self {
        self.keep_raw = keep;
        self
    }

    /// Read at most `bytes` of long values per row (default
    /// [`ROW_LONG_VALUE_LIMIT`]); the long values after that are NULL, with a
    /// problem. Every reference to a long value is read on its own, so a
    /// damaged or crafted record referring to one large long value thousands
    /// of times would otherwise need thousands of copies of it.
    #[must_use]
    pub fn long_value_limit(mut self, bytes: usize) -> Self {
        self.long_value_limit = bytes;
        self
    }

    /// What went wrong so far, in the order met.
    #[must_use]
    pub fn problems(&self) -> &[String] {
        &self.cursor.problems
    }

    fn row(&mut self, entry: &Entry<'a>) -> Row {
        self.row_long_value_bytes = 0;
        let context = format!("table {}, record on page {}", self.table.name, entry.page);
        let record = match Record::parse(entry.node.data, self.pages.tagged_format()) {
            Ok((record, damage)) => {
                if let Some(damage) = damage {
                    self.cursor.problems.push(format!("{context}: {damage}"));
                }
                record
            }
            Err(damage) => {
                self.cursor.problems.push(format!("{context}: {damage}"));
                let columns = self.table.columns.len();
                return Row {
                    page: entry.page,
                    values: vec![Value::Null; columns],
                    states: vec![ValueState::Damaged; columns],
                    raw: if self.keep_raw {
                        vec![None; columns]
                    } else {
                        Vec::new()
                    },
                };
            }
        };
        let table = self.table;
        let mut row = Row {
            page: entry.page,
            values: Vec::with_capacity(table.columns.len()),
            states: Vec::with_capacity(table.columns.len()),
            raw: Vec::new(),
        };
        for column in &table.columns {
            let mut problems = Vec::new();
            let (value, state, raw) = self.value(&record, column, &mut problems);
            let column_context = |problem| format!("{context}, column {}: {problem}", column.name);
            self.cursor
                .problems
                .extend(problems.into_iter().map(column_context));
            row.values.push(value);
            row.states.push(state);
            if self.keep_raw {
                row.raw.push(raw);
            }
        }
        row
    }

    /// `column`'s value in `record`, how it was read and its bytes; what
    /// went wrong is added to `problems`.
    fn value(&mut self, record: &Record<'a>, column: &Column, problems: &mut Vec<String>) -> Cell {
        let stored = match column.kind() {
            ColumnKind::Fixed => record.fixed(column),
            ColumnKind::Variable => record.variable(column.id),
            ColumnKind::Tagged => {
                // A derived table's tagged columns share identifiers with its
                // template's.
                let derived = self
                    .table
                    .template
                    .is_some()
                    .then_some(column.from_template);
                return match record.tagged(column.id, derived) {
                    Some(tagged) => self.tagged_value(tagged, column, problems),
                    None => (Value::Null, ValueState::Null, None),
                };
            }
        };
        let stored = stored.map(|bytes| bytes.map(Cow::Borrowed));
        cell(column, stored, self.keep_raw, problems)
    }

    /// A tagged column's value. Compression covers a long value's every
    /// segment, else a multi-value's first value, else the whole value.
    fn tagged_value(
        &mut self,
        tagged: &Tagged<'a>,
        column: &Column,
        problems: &mut Vec<String>,
    ) -> Cell {
        let flags = tagged.flags;
        let multi = flags.is_multi_value() || flags.is_two_values();
        let compressed_whole = flags.is_compressed() && (flags.is_long_value() || !multi);
        let data = self.plain(
            tagged.data,
            flags.is_long_value(),
            compressed_whole,
            problems,
        );
        if !multi {
            return cell(column, data.map(Some), self.keep_raw, problems);
        }
        let data = match data {
            Ok(data) => data,
            Err(problem) => return cell(column, Err(problem), self.keep_raw, problems),
        };
        let raw = || self.keep_raw.then(|| data.to_vec());
        let items = match split_multi_value(&data, flags.is_two_values()) {
            Ok(items) => items,
            Err(problem) => {
                problems.push(problem);
                return (Value::Null, ValueState::Damaged, raw());
            }
        };
        let raw = raw();
        let compressed_first = flags.is_compressed() && !compressed_whole;
        let mut state = if value::unsupported(column.column_type) {
            ValueState::Unsupported
        } else {
            ValueState::Parsed
        };
        let values = items
            .into_iter()
            .enumerate()
            .map(|(index, item)| {
                let compressed = compressed_first && index == 0;
                let value = self
                    .plain(item.data, item.separated, compressed, problems)
                    .and_then(|bytes| value::decode(column, &bytes))
                    .map_err(|problem| format!("value {index}: {problem}"));
                value.unwrap_or_else(|problem| {
                    problems.push(problem);
                    state = ValueState::Damaged;
                    Value::Null
                })
            })
            .collect();
        (Value::MultiValue(values), state, raw)
    }

    /// The plain bytes of stored `data`: the long value it identifies, or
    /// it decompressed, or itself.
    fn plain<'d>(
        &mut self,
        data: &'d [u8],
        long_value: bool,
        compressed: bool,
        problems: &mut Vec<String>,
    ) -> Result<Cow<'d, [u8]>, String> {
        if long_value {
            self.long_value(data, compressed, problems).map(Cow::Owned)
        } else if compressed {
            compression::decompress(data).map(Cow::Owned)
        } else {
            Ok(Cow::Borrowed(data))
        }
    }

    /// The data of the long value `id`, from the table's long value tree
    /// (read on first use). The bytes before any damage are kept, the
    /// damage added to `problems`.
    fn long_value(
        &mut self,
        id: &[u8],
        compressed: bool,
        problems: &mut Vec<String>,
    ) -> Result<Vec<u8>, String> {
        let long_values = match &mut self.long_values {
            Some(long_values) => long_values,
            unread @ None => {
                let root = self
                    .table
                    .long_value_root
                    .ok_or("a long value, but the table has no long value tree")?;
                let (long_values, damage) = LongValues::read(self.pages, root);
                let table = &self.table.name;
                let in_tree = |problem| format!("table {table}, long value tree: {problem}");
                self.cursor.problems.extend(damage.into_iter().map(in_tree));
                unread.insert(long_values)
            }
        };
        if self.row_long_value_bytes >= self.long_value_limit {
            return Err(format!(
                "the row's long values reached the limit of {} bytes, the rest are not read",
                self.long_value_limit
            ));
        }
        let (data, damage) = long_values.get(id, compressed)?;
        self.row_long_value_bytes = self.row_long_value_bytes.saturating_add(data.len());
        problems.extend(damage);
        Ok(data)
    }
}

/// The value of `column` stored as `stored` (`None`: NULL), how it was read,
/// and, when `keep_raw`, its bytes; what went wrong is added to `problems`.
/// The bytes are those stored, also when they don't decode; there are none
/// for a NULL or when the damage came before any could be read.
fn cell(
    column: &Column,
    stored: Result<Option<Cow<'_, [u8]>>, String>,
    keep_raw: bool,
    problems: &mut Vec<String>,
) -> Cell {
    let bytes = match stored {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return (Value::Null, ValueState::Null, None),
        Err(problem) => {
            problems.push(problem);
            return (Value::Null, ValueState::Damaged, None);
        }
    };
    let (value, state) = match value::decode(column, &bytes) {
        Ok(value) if value::unsupported(column.column_type) => (value, ValueState::Unsupported),
        Ok(value) => (value, ValueState::Parsed),
        Err(problem) => {
            problems.push(problem);
            (Value::Null, ValueState::Damaged)
        }
    };
    (value, state, keep_raw.then(|| bytes.into_owned()))
}

impl Iterator for Rows<'_> {
    type Item = Row;

    fn next(&mut self) -> Option<Row> {
        let entry = self.cursor.next_entry()?;
        Some(self.row(&entry))
    }
}

/// One of the values of a multi-valued column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Item<'a> {
    /// Whether `data` is a long value identifier.
    separated: bool,
    data: &'a [u8],
}

/// Split a multi-value: an array of 16-bit offsets (its size given by the
/// first) then the values, each up to the next one's offset; or, flagged
/// "two values", a byte with the first value's size then both values.
fn split_multi_value(data: &[u8], two_values: bool) -> Result<Vec<Item<'_>>, String> {
    let item = |data| Item {
        separated: false,
        data,
    };
    if two_values {
        let first_size = usize::from(u8_at(data, 0).ok_or("an empty pair of values")?);
        let (first, second) = data
            .get(1..)
            .filter(|rest| rest.len() >= first_size)
            .map(|rest| rest.split_at(first_size))
            .ok_or_else(|| format!("first of two values of {first_size} bytes cut short"))?;
        return Ok(vec![item(first), item(second)]);
    }
    let offset = |index: usize| u16_at(data, index * MULTI_VALUE_OFFSET_SIZE);
    let first = offset(0).ok_or("an empty multi-value")?;
    let count = usize::from(first & MULTI_VALUE_OFFSET_MASK) / MULTI_VALUE_OFFSET_SIZE;
    if count == 0 || count * MULTI_VALUE_OFFSET_SIZE > data.len() {
        return Err(format!(
            "multi-value offset {first:#06x} outside its {} bytes",
            data.len()
        ));
    }
    (0..count)
        .map(|index| {
            let raw = offset(index).unwrap_or_default();
            let start = usize::from(raw & MULTI_VALUE_OFFSET_MASK);
            let end = match offset(index + 1).filter(|_| index + 1 < count) {
                Some(next) => usize::from(next & MULTI_VALUE_OFFSET_MASK),
                None => data.len(),
            };
            data.get(start..end)
                .filter(|_| start >= count * MULTI_VALUE_OFFSET_SIZE)
                .map(|value| Item {
                    separated: raw & SEPARATED_VALUE != 0,
                    data: value,
                })
                .ok_or_else(|| {
                    format!("value {index} from {start} to {end} outside the multi-value")
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ColumnType;

    fn column(column_type: ColumnType) -> Column {
        Column {
            id: 1,
            name: "c".to_owned(),
            column_type,
            codepage: 1252,
            flags: 0,
            max_size: 0,
            record_offset: 4,
            default: None,
            from_template: false,
        }
    }

    fn stored(bytes: &[u8]) -> Cow<'_, [u8]> {
        Cow::Borrowed(bytes)
    }

    #[test]
    fn each_value_says_how_it_was_read() {
        let long = column(ColumnType::Long);
        let mut problems = Vec::new();
        let one = 1i32.to_le_bytes();
        assert_eq!(
            cell(&long, Ok(Some(stored(&one))), true, &mut problems),
            (Value::I32(1), ValueState::Parsed, Some(one.to_vec()))
        );
        assert_eq!(
            cell(&long, Ok(Some(stored(&one))), false, &mut problems),
            (Value::I32(1), ValueState::Parsed, None)
        );
        // NULL: no bytes, none made up
        assert_eq!(
            cell(&long, Ok(None), true, &mut problems),
            (Value::Null, ValueState::Null, None)
        );
        assert_eq!(problems, Vec::<String>::new());
        // stored but not decodable: its bytes, and the problem
        assert_eq!(
            cell(&long, Ok(Some(stored(&[1, 2]))), true, &mut problems),
            (Value::Null, ValueState::Damaged, Some(vec![1, 2]))
        );
        // damage before any bytes could be read
        assert_eq!(
            cell(&long, Err("cut short".to_owned()), true, &mut problems),
            (Value::Null, ValueState::Damaged, None)
        );
        assert_eq!(
            problems,
            ["2 bytes for a Long value of 4 bytes", "cut short"]
        );
        // no decoding for the type: its bytes
        assert_eq!(
            cell(
                &column(ColumnType::Slv),
                Ok(Some(stored(&[7]))),
                true,
                &mut problems
            ),
            (
                Value::Binary(vec![7]),
                ValueState::Unsupported,
                Some(vec![7])
            )
        );
        // the ends of the ranges, whole
        let max = u64::MAX.to_le_bytes();
        assert_eq!(
            cell(
                &column(ColumnType::UnsignedLongLong),
                Ok(Some(stored(&max))),
                false,
                &mut problems
            )
            .0,
            Value::U64(u64::MAX)
        );
        let min = i64::MIN.to_le_bytes();
        assert_eq!(
            cell(
                &column(ColumnType::LongLong),
                Ok(Some(stored(&min))),
                false,
                &mut problems
            )
            .0,
            Value::I64(i64::MIN)
        );
        assert_eq!(problems.len(), 2);
    }

    #[test]
    fn multi_values_follow_their_offsets() {
        // Three values: "ab", "", and a long value identifier.
        let data = [6, 0, 8, 0, 8, 0x80, b'a', b'b', 7, 0, 0, 0];
        let items = split_multi_value(&data, false).unwrap();
        let datas: Vec<_> = items
            .iter()
            .map(|item| (item.separated, item.data))
            .collect();
        assert_eq!(
            datas,
            [
                (false, &b"ab"[..]),
                (false, &b""[..]),
                (true, &[7, 0, 0, 0][..])
            ]
        );
    }

    #[test]
    fn two_values_start_with_the_first_size() {
        // From the libesedb format documentation: "link" then "program".
        let mut data = vec![8];
        data.extend("linkprogram".encode_utf16().flat_map(u16::to_le_bytes));
        let items = split_multi_value(&data, true).unwrap();
        assert_eq!(items[0].data.len(), 8);
        assert_eq!(items[1].data.len(), 14);
    }

    #[test]
    fn damaged_multi_values_are_errors() {
        assert!(split_multi_value(&[], false).is_err());
        assert!(split_multi_value(&[40, 0, 1], false).is_err());
        assert!(split_multi_value(&[4, 0, 9, 0, 1], false).is_err());
        assert!(split_multi_value(&[9, 1], true).is_err());
    }
}
