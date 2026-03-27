use chrono::{TimeZone, Utc};
use libc::timeval;

pub fn timeval_to_string(tv: timeval) -> String {
    let datetime = Utc.timestamp_opt(tv.tv_sec as i64, tv.tv_usec as u32 * 1000);
    datetime.unwrap().to_string()
}
