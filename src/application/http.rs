use std::fmt::Display;

use bytes::Bytes;

use crate::traits::Protocol;

#[derive(Clone, PartialEq)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

#[derive(Clone, PartialEq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

#[derive(Clone, PartialEq)]
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

    fn format_protocol(protocol: HttpMessage) -> String {
        protocol.to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_request_and_body() {
        let parsed = HttpMessage::parse(Bytes::from_static(
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\nbody",
        ))
        .unwrap();

        match parsed {
            HttpMessage::Request(req) => {
                assert_eq!(req.method, "GET");
                assert_eq!(req.path, "/index.html");
                assert_eq!(req.version, "HTTP/1.1");
                assert_eq!(
                    req.headers,
                    vec![("Host".to_string(), "example.com".to_string())]
                );
                assert_eq!(req.body, Bytes::from_static(b"body"));
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn parses_http_response_and_rejects_malformed_headers() {
        let parsed = HttpMessage::parse(Bytes::from_static(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        ))
        .unwrap();

        match parsed {
            HttpMessage::Response(res) => {
                assert_eq!(res.version, "HTTP/1.1");
                assert_eq!(res.status, 404);
                assert_eq!(res.reason, "Not Found");
            }
            _ => panic!("expected response"),
        }

        assert!(HttpMessage::parse(Bytes::from_static(b"GET / HTTP/1.1\r\n")).is_none());
        assert!(HttpMessage::parse(Bytes::from_static(b"HTTP/1.1 nope\r\n\r\n")).is_none());
    }
}
