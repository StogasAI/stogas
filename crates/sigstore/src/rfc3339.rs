//! RFC 3339 times in UTC, as TUF metadata, Sigstore's protobuf JSON and Stogas services write them.

use der::DateTime;
use std::time::Duration;

/// Time since the Unix epoch of a time such as `2021-03-07T03:20:29Z`, with up to nine digits
/// of a fraction of a second, from 1970 through 9999.
///
/// These writers always use `Z`, so an offset, a lowercase separator or a leap second is
/// refused instead of interpreted.
#[must_use]
pub fn unix_time(value: &str) -> Option<Duration> {
    let (seconds, fraction) = value.strip_suffix('Z')?.split_at_checked(19)?;
    let nanos = match fraction.strip_prefix('.') {
        None if fraction.is_empty() => 0,
        Some(digits)
            if (1..=9).contains(&digits.len())
                && digits.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            format!("{digits:0<9}").parse().ok()?
        }
        _ => return None,
    };
    // `DateTime` reads exactly `YYYY-MM-DDTHH:MM:SSZ` and checks each field and the calendar.
    let time: DateTime = format!("{seconds}Z").parse().ok()?;
    Some(time.unix_duration() + Duration::from_nanos(nanos))
}

#[cfg(test)]
mod tests {
    use super::unix_time;
    use std::time::Duration;

    #[test]
    fn reads_utc_times_with_any_fraction() {
        let time = |seconds, nanos| Some(Duration::new(seconds, nanos));
        assert_eq!(unix_time("1970-01-01T00:00:00Z"), time(0, 0));
        assert_eq!(unix_time("2021-03-07T03:20:29Z"), time(1_615_087_229, 0));
        assert_eq!(
            unix_time("2021-03-07T03:20:29.000Z"),
            time(1_615_087_229, 0)
        );
        assert_eq!(
            unix_time("2021-03-07T03:20:29.5Z"),
            time(1_615_087_229, 500_000_000)
        );
        assert_eq!(
            unix_time("2024-02-29T23:59:59.123456789Z"),
            time(1_709_251_199, 123_456_789)
        );
        assert_eq!(unix_time("9999-12-31T23:59:59Z"), time(253_402_300_799, 0));
    }

    #[test]
    fn refuses_every_other_form() {
        for value in [
            "",
            "2021-03-07",
            "2021-03-07T03:20:29",
            "2021-03-07T03:20:29+00:00",
            "2021-03-07T04:20:29+01:00",
            "2021-03-07t03:20:29z",
            "2021-03-07 03:20:29Z",
            "2021-03-07T03:20Z",
            "2021-03-07T03:20:29.Z",
            "2021-03-07T03:20:29.1234567890Z",
            "2021-03-07T03:20:29.+12Z",
            "2021-03-07T03:20:29,5Z",
            "2021-03-07T03:20:29ZZ",
            "2021-03-07T03:20:60Z",
            "2021-03-07T24:00:00Z",
            "2021-02-29T00:00:00Z",
            "2021-13-01T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "+2021-03-07T03:20:29Z",
            "２021-03-07T03:20:29Z",
        ] {
            assert_eq!(unix_time(value), None, "{value}");
        }
    }
}
