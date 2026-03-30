use std::fmt::Display;

pub enum HttpMessage<'a> {
    Request(HttpRequest<'a>),
    Response(HttpResponse<'a>),
}

pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub version: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body: &'a [u8],
}

pub struct HttpResponse<'a> {
    pub version: &'a str,
    pub status: u16,
    pub reason: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body: &'a [u8],
}

impl<'a> HttpMessage<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let text = std::str::from_utf8(data).ok()?;

        let (header, _) = text.split_once("\r\n\r\n")?;
        let mut header_lines = header.lines();

        let first_line = header_lines.next()?;

        let headers: Vec<(&str, &str)> = header_lines.filter_map(|l| l.split_once(": ")).collect();

        let header_len = header.len() + 4;
        let body_bytes = &data[header_len..];

        if first_line.starts_with("HTTP/") {
            let mut parts = first_line.splitn(3, " ");
            let version = parts.next()?;
            let status_str = parts.next()?;
            let reason = parts.next().unwrap_or("");
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
            let method = parts.next()?;
            let path = parts.next()?;
            let version = parts.next()?;

            Some(HttpMessage::Request(HttpRequest {
                method,
                path,
                version,
                headers,
                body: body_bytes,
            }))
        }
    }
}

impl Display for HttpMessage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMessage::Request(req) => write!(f, "{}", req),
            HttpMessage::Response(res) => write!(f, "{}", res),
        }
    }
}

impl Display for HttpRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[HTTP] {} {} {}", self.method, self.path, self.version)
    }
}

impl Display for HttpResponse<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[HTTP] {} {} {}", self.version, self.status, self.reason)
    }
}
