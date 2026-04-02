use bytes::Bytes;
use libc::timeval;

pub trait Protocol: Sized {
    fn parse(data: Bytes) -> Option<Self>;

    fn format_protocol(count: u64, ts: timeval, protocol: Self) -> String;
}
