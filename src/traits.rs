use bytes::Bytes;

pub trait Protocol: Sized {
    fn parse(data: Bytes) -> Option<Self>;

    fn format_protocol(protocol: Self) -> String;
}
