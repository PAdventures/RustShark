use std::fmt::Display;

use bytes::Bytes;
use libc::timeval;

use crate::{traits::Protocol, utils::timeval_to_string};

#[derive(Clone)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

#[derive(Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

#[derive(Clone)]
pub struct HttpResponse {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl Protocol for HttpMessage {
    fn parse(data: Bytes) -> Option<Self> {
        let text = String::from_utf8_lossy(&data);

        let (header, _) = text.split_once("\r\n\r\n")?;
        let mut header_lines = header.lines();

        let first_line = header_lines.next()?;

        let headers: Vec<(String, String)> = header_lines
            .filter_map(|l| l.split_once(": ").to_owned())
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();

        let header_len = header.len() + 4;
        let body_bytes = data.slice(header_len..);

        if first_line.starts_with("HTTP/") {
            let mut parts = first_line.splitn(3, " ");
            let version = parts.next()?.to_owned();
            let status_str = parts.next()?;
            let reason = parts.next().unwrap_or("").to_owned();
            let status = u16::from_str_radix(status_str, 10).ok()?;

            Some(HttpMessage::Response(HttpResponse {
                version,
                status,
                reason,
                headers,
                body: body_bytes,
            }))
        } else {
            let mut parts = first_line.splitn(3, ' ');
            let method = parts.next()?.to_owned();
            let path = parts.next()?.to_owned();
            let version = parts.next()?.to_owned();

            Some(HttpMessage::Request(HttpRequest {
                method,
                path,
                version,
                headers,
                body: body_bytes,
            }))
        }
    }

    fn format_protocol(count: u64, ts: timeval, protocol: HttpMessage) -> String {
        format!("{count} {} {}", timeval_to_string(ts), protocol.to_string())
    }
}

impl Display for HttpMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMessage::Request(req) => write!(f, "{}", req),
            HttpMessage::Response(res) => write!(f, "{}", res),
        }
    }
}

impl Display for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[HTTP] {} {} {}", self.method, self.path, self.version)
    }
}

impl Display for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[HTTP] {} {} {}", self.version, self.status, self.reason)
    }
}
