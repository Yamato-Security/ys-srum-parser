//! The times SRUM records: `TimeStamp` as an OLE automation date, and
//! FILETIMEs (`ConnectStartTime`, `EventTimestamp`, `EndTime`, …) stored as
//! 64-bit integers. Replaces sootmark-common's general `Ts` (MIT OR
//! Apache-2.0), with the same conversions.

use core::fmt;

const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_MILLI: i64 = 10_000;
const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;
const MILLIS_PER_DAY: f64 = 86_400_000.0;
/// FILETIME ticks between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_OFFSET: i64 = 116_444_736_000_000_000;
/// Seconds from 1970-01-01 back to 1899-12-30, the OLE automation epoch.
const OLE_EPOCH_UNIX_SECONDS: i64 = -2_209_161_600;
/// OLE dates further than this from the epoch are not times (±27,000 years).
const MAX_OLE_DAYS: f64 = 10_000_000.0;

/// A UTC time, in 100 ns ticks since 1970-01-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Time(i64);

impl Time {
    /// An OLE automation date: days since 1899-12-30, the fraction being the
    /// time of day (for negative days the fraction still counts forward from
    /// midnight), to the millisecond. `None` for `0.0` (never set) and for
    /// values that are not times.
    #[must_use]
    pub fn from_ole_date(days: f64) -> Option<Self> {
        if days == 0.0 || !days.is_finite() || days.abs() > MAX_OLE_DAYS {
            return None;
        }
        let whole = days.trunc();
        let fraction = (days - whole).abs();
        let millis_of_day = (fraction * MILLIS_PER_DAY).round() as i64;
        Some(Self(
            (whole as i64) * TICKS_PER_DAY
                + millis_of_day * TICKS_PER_MILLI
                + OLE_EPOCH_UNIX_SECONDS * TICKS_PER_SECOND,
        ))
    }

    /// A FILETIME: 100 ns intervals since 1601-01-01. `None` for 0 (never
    /// set), the `0x7FFF_FFFF_FFFF_FFFF` sentinel and negative values.
    #[must_use]
    pub fn from_filetime(value: i64) -> Option<Self> {
        match value {
            i64::MAX => None,
            v if v > 0 => Some(Self(v - FILETIME_UNIX_OFFSET)),
            _ => None,
        }
    }

    /// 100 ns ticks since 1970-01-01 UTC.
    #[must_use]
    pub const fn unix_ticks(self) -> i64 {
        self.0
    }

    /// `YYYY-MM-DDTHH:MM:SS.fffffffZ`; years outside 0000-9999 use the
    /// expanded `±YYYYYY` form.
    #[must_use]
    pub fn to_iso8601(self) -> String {
        let days = self.0.div_euclid(TICKS_PER_DAY);
        let rem = self.0.rem_euclid(TICKS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let secs = rem / TICKS_PER_SECOND;
        let frac = rem % TICKS_PER_SECOND;
        let year = if (0..=9999).contains(&year) {
            format!("{year:04}")
        } else {
            format!("{year:+07}")
        };
        format!(
            "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{frac:07}Z",
            secs / 3600,
            secs / 60 % 60,
            secs % 60,
        )
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_iso8601())
    }
}

/// Proleptic Gregorian `(year, month, day)` for days since 1970-01-01
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ole_dates() {
        let iso = |days: f64| Time::from_ole_date(days).map(Time::to_iso8601);
        assert_eq!(iso(1.5).as_deref(), Some("1899-12-31T12:00:00.0000000Z"));
        // -1.25: the day before the epoch, 06:00
        assert_eq!(iso(-1.25).as_deref(), Some("1899-12-29T06:00:00.0000000Z"));
        // a SRUM TimeStamp: 2022-03-10 16:34:59 (to the millisecond)
        assert_eq!(
            iso(44_630.690_960_648_15).as_deref(),
            Some("2022-03-10T16:34:59.0000000Z")
        );
        assert_eq!(iso(0.0), None);
        assert_eq!(iso(f64::NAN), None);
        assert_eq!(iso(1e9), None);
    }

    #[test]
    fn filetimes() {
        let iso = |ft: i64| Time::from_filetime(ft).map(Time::to_iso8601);
        assert_eq!(
            iso(133_515_874_611_440_142).as_deref(),
            Some("2024-02-05T06:17:41.1440142Z")
        );
        assert_eq!(iso(1).as_deref(), Some("1601-01-01T00:00:00.0000001Z"));
        assert_eq!(iso(0), None);
        assert_eq!(iso(-5), None);
        assert_eq!(iso(i64::MAX), None);
    }
}
