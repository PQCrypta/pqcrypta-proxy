//! The `multipart/form-data` request body processor.
//!
//! It follows libmodsecurity v3's (`src/request_body_processor/multipart.cc`):
//! the boundary's checks in the Content-Type, the body read line by line, the
//! part headers and their Content-Disposition parsed as strictly, and the
//! flags behind `MULTIPART_STRICT_ERROR`, which a deployment denies on (the
//! recommended rule 200003). The body is bytes: a file part is never decoded
//! as text to be split.
//!
//! Two departures, both where ModSecurity's behaviour is a gap rather than a
//! semantic: an empty boundary (`boundary=`) is an error here, where v3 stops
//! without one and leaves the body uninspected; and the file limit
//! (`MULTIPART_FILE_LIMIT_EXCEEDED`) is never reached, because v3 checks it
//! only when it writes uploads to disk, which this engine never does.

/// What the strict checks found, each backing a `MULTIPART_*` variable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MultipartFlags {
    /// `MULTIPART_BOUNDARY_QUOTED`: the boundary was quoted in the Content-Type.
    pub boundary_quoted: bool,
    /// `MULTIPART_BOUNDARY_WHITESPACE`: whitespace around `boundary=`.
    pub boundary_whitespace: bool,
    /// `MULTIPART_MISSING_SEMICOLON`: no `;` before the boundary parameter.
    pub missing_semicolon: bool,
    /// `MULTIPART_DATA_BEFORE`: content before the first boundary.
    pub data_before: bool,
    /// `MULTIPART_DATA_AFTER`: content after the final boundary.
    pub data_after: bool,
    /// `MULTIPART_HEADER_FOLDING`: a part header continued on the next line.
    pub header_folding: bool,
    /// `MULTIPART_INVALID_HEADER_FOLDING`: folded with neither space nor tab.
    pub invalid_header_folding: bool,
    /// `MULTIPART_LF_LINE`: a header or boundary line ended in LF alone.
    pub lf_line: bool,
    /// A header or boundary line ended in CRLF (with `lf_line`,
    /// `MULTIPART_CRLF_LF_LINES`: mixed line endings).
    pub crlf_line: bool,
    /// `MULTIPART_INVALID_QUOTING`: single quotes, an unterminated quote, or a
    /// quote where a separator belongs, in a Content-Disposition.
    pub invalid_quoting: bool,
    /// `MULTIPART_INVALID_PART`: a part without a name, a boundary where a
    /// part's data should begin, or a bad escape in `filename*`.
    pub invalid_part: bool,
    /// A part header, or a Content-Disposition parameter, given twice.
    pub duplicate_part_header: bool,
    /// `MULTIPART_FILE_LIMIT_EXCEEDED` (see the module note: never set).
    pub file_limit_exceeded: bool,
    /// `MULTIPART_UNMATCHED_BOUNDARY`: 1 for a line that looks like a
    /// boundary but is not this body's, 2 for a delimiter after the first
    /// (as v3 reports it). Not part of the strict error.
    pub unmatched_boundary: u8,
    /// Parsing stopped on an error (v3's `m_flag_error`).
    pub fatal: bool,
}

impl MultipartFlags {
    /// `MULTIPART_STRICT_ERROR`: the flags v3 ORs into it.
    pub fn strict_error(&self) -> bool {
        self.fatal
            || self.boundary_quoted
            || self.boundary_whitespace
            || self.data_before
            || self.data_after
            || self.duplicate_part_header
            || self.header_folding
            || self.lf_line
            || self.missing_semicolon
            || self.invalid_quoting
            || self.invalid_part
            || self.invalid_header_folding
            || self.file_limit_exceeded
    }
}

/// One named part of the body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Part {
    /// The Content-Disposition `name`.
    pub name: String,
    /// The file name, `filename*` (decoded) over `filename`, for a file part.
    pub filename: Option<String>,
    /// The part's content, its framing removed.
    pub value: Vec<u8>,
}

/// What the processor extracted, and what it found wrong.
#[derive(Debug, Clone, Default)]
pub struct Multipart {
    /// The named parts, in order. A part without a name is dropped (and
    /// `invalid_part` set), as in v3.
    pub parts: Vec<Part>,
    /// `MULTIPART_PART_HEADERS`: (part name, the header line as received,
    /// without its line ending; a folded header joined with one space), for
    /// every part, named or not.
    pub part_headers: Vec<(String, String)>,
    /// The flags.
    pub flags: MultipartFlags,
    /// The first error, for `REQBODY_ERROR_MSG`; any error sets `REQBODY_ERROR`.
    pub error: Option<String>,
}

impl Multipart {
    fn fail(&mut self, msg: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(msg.into());
        }
    }

    fn fatal(&mut self, msg: impl Into<String>) {
        self.flags.fatal = true;
        self.fail(msg);
    }
}

/// Longest part header v3 accepts, folded lines joined.
const MAX_HEADER: usize = 4096;

/// Parse a `multipart/form-data` body given its Content-Type.
pub fn parse(content_type: &str, body: &[u8]) -> Multipart {
    let mut mp = Multipart::default();
    let boundary = match boundary(content_type.trim_start(), &mut mp.flags) {
        Ok(b) => b,
        Err(e) => {
            mp.fatal(e);
            return mp;
        }
    };
    Parser::new(&boundary, &mut mp).run(body);
    mp
}

/// `count_boundary_params`: occurrences of `boundary` (any case) with an `=`
/// somewhere after them.
fn boundary_params(s: &str) -> usize {
    let lower = s.to_ascii_lowercase();
    lower
        .match_indices("boundary")
        .filter(|(i, _)| lower[i + 8..].contains('='))
        .count()
}

/// RFC 2046's boundary characters, as v3 checks them: a space, not last.
fn boundary_characters_valid(b: &str) -> bool {
    let bytes = b.as_bytes();
    !bytes.is_empty()
        && bytes.iter().enumerate().all(|(i, &c)| {
            c.is_ascii_alphanumeric()
                || b"'()+_,-./:=?".contains(&c)
                || (c == b' ' && i + 1 < bytes.len())
        })
}

/// The boundary, from the Content-Type, with v3's checks and flags.
fn boundary(ct: &str, flags: &mut MultipartFlags) -> Result<String, String> {
    const MIME: &str = "multipart/form-data";
    if ct.len() > 1024 {
        return Err("Multipart: Invalid boundary in C-T (length).".into());
    }
    if ct.len() < MIME.len() || !ct[..MIME.len()].eq_ignore_ascii_case(MIME) {
        return Err("Multipart: Invalid MIME type.".into());
    }
    if boundary_params(ct) > 1 {
        return Err("Multipart: Multiple boundary parameters in C-T.".into());
    }
    let Some(at) = ct.find("boundary") else {
        return Err(if boundary_params(ct) > 0 {
            "Multipart: Invalid boundary in C-T (case sensitivity).".into()
        } else {
            "Multipart: Boundary not found in C-T.".into()
        });
    };
    if at < MIME.len() {
        return Err("Multipart: Invalid boundary in C-T (malformed).".into());
    }
    // Only whitespace and one `;` between the media type and the parameter
    let mut semicolon = false;
    for c in ct[MIME.len()..at].bytes() {
        match c {
            b';' if !semicolon => semicolon = true,
            c if c.is_ascii_whitespace() => {}
            _ => return Err("Multipart: Invalid boundary in C-T (malformed).".into()),
        }
    }
    if !semicolon {
        flags.missing_semicolon = true;
    }
    let after = at + "boundary".len();
    let Some(eq) = ct[after..].find('=') else {
        return Err("Multipart: Invalid boundary in C-T (malformed).".into());
    };
    for c in ct[after..after + eq].bytes() {
        if c.is_ascii_whitespace() {
            flags.boundary_whitespace = true;
        } else {
            return Err("Multipart: Invalid boundary in C-T (parameter name).".into());
        }
    }
    let value = &ct[after + eq + 1..];
    if value.starts_with(|c: char| c.is_ascii_whitespace()) {
        flags.boundary_whitespace = true;
    }
    let mut b = if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        flags.boundary_quoted = true;
        &value[1..value.len() - 1]
    } else if value.starts_with('"') || value.ends_with('"') {
        return Err("Multipart: Invalid boundary in C-T (quote).".into());
    } else {
        value
    };
    if b.is_empty() {
        return Err("Multipart: Invalid boundary in C-T (empty).".into());
    }
    if boundary_params(b) != 0 {
        return Err("Multipart: Invalid boundary in C-T (content).".into());
    }
    if !boundary_characters_valid(b) {
        // A parameter after the boundary (`boundary=x; charset=utf-8`)
        b = b.split(';').next().unwrap_or_default();
        if !boundary_characters_valid(b) {
            return Err("Multipart: Invalid boundary in C-T (characters).".into());
        }
    }
    Ok(b.to_string())
}

/// How a line ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    Crlf,
    Lf,
    /// The body ended without one.
    None,
}

impl Ending {
    fn bytes(self) -> &'static [u8] {
        match self {
            Ending::Crlf => b"\r\n",
            Ending::Lf => b"\n",
            Ending::None => b"",
        }
    }
}

/// The part being read.
#[derive(Default)]
struct Current {
    name: String,
    filename: Option<Vec<u8>>,
    filename_star: Option<Vec<u8>>,
    /// (name, value, the line as received)
    headers: Vec<(String, String, String)>,
    value: Vec<u8>,
    in_headers: bool,
    data_read: bool,
}

struct Parser<'a> {
    boundary: &'a [u8],
    mp: &'a mut Multipart,
    current: Option<Current>,
    boundaries: usize,
    complete: bool,
    /// The previous data line's ending, which belongs to the content only if
    /// another data line follows (before a delimiter it is the delimiter's)
    held: Ending,
}

impl<'a> Parser<'a> {
    fn new(boundary: &'a str, mp: &'a mut Multipart) -> Self {
        Parser {
            boundary: boundary.as_bytes(),
            mp,
            current: None,
            boundaries: 0,
            complete: false,
            held: Ending::None,
        }
    }

    fn run(mut self, body: &[u8]) {
        let mut pos = 0;
        while pos < body.len() {
            let (line, next) = match body[pos..].iter().position(|&c| c == b'\n') {
                Some(i) => (&body[pos..=pos + i], pos + i + 1),
                None => (&body[pos..], body.len()),
            };
            pos = next;
            if self.complete {
                self.mp.flags.data_after = true;
                break;
            }
            let (content, ending) = if let Some(c) = line.strip_suffix(b"\r\n") {
                (c, Ending::Crlf)
            } else if let Some(c) = line.strip_suffix(b"\n") {
                (c, Ending::Lf)
            } else {
                (line, Ending::None)
            };
            if !self.line(content, ending) {
                return;
            }
        }
        self.finish();
    }

    /// One line; false when parsing must stop.
    fn line(&mut self, content: &[u8], ending: Ending) -> bool {
        let b = self.boundary;
        if content.len() >= b.len() + 2
            && content.starts_with(b"--")
            && &content[2..2 + b.len()] == b
        {
            let data_read = self.current.as_ref().is_none_or(|c| c.data_read);
            if !data_read && self.boundaries > 0 {
                // A delimiter where the part's data should begin: v3 does not
                // take it as one
                self.mp.flags.invalid_part = true;
            } else {
                return self.delimiter(&content[2 + b.len()..], ending);
            }
        }
        let Some(current) = self.current.as_mut() else {
            // Before the first boundary: ignored, and flagged
            self.mp.flags.data_before = true;
            return true;
        };
        if current.in_headers {
            self.header(content, ending);
            return true;
        }
        // Part data
        if (content.len() > 3 && content.starts_with(b"--"))
            || contains(content, &[b"--", b].concat())
        {
            self.mp.flags.unmatched_boundary = 1;
        }
        let current = self.current.as_mut().expect("checked above");
        current.value.extend_from_slice(self.held.bytes());
        current.value.extend_from_slice(content);
        current.data_read = true;
        self.held = ending;
        true
    }

    /// A line holding the boundary; `rest` is what follows it on the line.
    fn delimiter(&mut self, rest: &[u8], ending: Ending) -> bool {
        let is_final = rest.starts_with(b"--");
        let rest = if is_final { &rest[2..] } else { rest };
        if is_final && self.complete {
            self.mp
                .fatal("Multipart: Invalid boundary (final duplicate).");
            return false;
        }
        // The boundary must end its line; at the end of the body only the
        // final one may go unterminated
        if !rest.is_empty() || (ending == Ending::None && !is_final) {
            self.mp.fatal("Multipart: Invalid boundary (extra data).");
            return false;
        }
        match ending {
            Ending::Crlf => self.mp.flags.crlf_line = true,
            Ending::Lf => self.mp.flags.lf_line = true,
            Ending::None => {}
        }
        // The data line before ended in LF alone
        if self.held == Ending::Lf {
            self.mp.flags.lf_line = true;
        }
        if self.boundaries > 0 {
            self.mp.flags.unmatched_boundary = 2;
        }
        self.close_part();
        if is_final {
            self.complete = true;
        } else {
            self.current = Some(Current {
                in_headers: true,
                ..Current::default()
            });
        }
        self.boundaries += 1;
        self.held = Ending::None;
        true
    }

    /// v3's `process_boundary`: the part read so far is kept if it has a name.
    fn close_part(&mut self) {
        let Some(c) = self.current.take() else {
            return;
        };
        for (_, _, line) in &c.headers {
            self.mp.part_headers.push((c.name.clone(), line.clone()));
        }
        if c.name.is_empty() {
            self.mp.flags.invalid_part = true;
            return;
        }
        let star = c.filename_star.filter(|f| !f.is_empty());
        let plain = c.filename.filter(|f| !f.is_empty());
        self.mp.parts.push(Part {
            name: c.name,
            filename: star.or(plain).map(|f| crate::bytes::text(&f)),
            value: c.value,
        });
    }

    /// v3's `process_part_header`, for one line of a part's head. Errors are
    /// recorded and parsing goes on, as there.
    fn header(&mut self, content: &[u8], ending: Ending) {
        match ending {
            Ending::Crlf => self.mp.flags.crlf_line = true,
            Ending::Lf | Ending::None => self.mp.flags.lf_line = true,
        }
        if content.contains(&0) {
            self.mp.fail("Multipart: Nul byte in part headers.");
            return;
        }
        if content.is_empty() {
            self.end_of_headers();
            return;
        }
        if content[0].is_ascii_whitespace() || content[0] == 0x0b {
            self.mp.flags.header_folding = true;
            if content[0] != b' ' && content[0] != b'\t' {
                self.mp.flags.invalid_header_folding = true;
            }
            let current = self.current.as_mut().expect("in a part");
            let Some(last) = current.headers.last_mut() else {
                self.mp
                    .fail("Multipart: Invalid part header (folding error).");
                return;
            };
            let more = crate::bytes::text(trim_start(content));
            last.1.push(' ');
            last.1.push_str(&more);
            last.2.push(' ');
            last.2.push_str(&more);
            if last.1.len() > MAX_HEADER {
                self.mp.fail("Multipart: Part header too long.");
            }
            return;
        }
        let Some(colon) = content.iter().position(|&c| c == b':') else {
            self.mp
                .fail("Multipart: Invalid part header (colon missing).");
            return;
        };
        let name = &content[..colon];
        if name.is_empty() {
            self.mp
                .fail("Multipart: Invalid part header (header name missing).");
            return;
        }
        if name.iter().any(|&c| !(33..=126).contains(&c)) {
            self.mp
                .fail("Multipart: Invalid part header (contains invalid character).");
            return;
        }
        let name = crate::bytes::text(name);
        let value = crate::bytes::text(trim_start(&content[colon + 1..]))
            .trim_end_matches(['\r', '\n'])
            .to_string();
        let current = self.current.as_mut().expect("in a part");
        if current
            .headers
            .iter()
            .any(|(n, _, _)| n.eq_ignore_ascii_case(&name))
        {
            self.mp.flags.duplicate_part_header = true;
            return;
        }
        let line = crate::bytes::text(content);
        current.headers.push((name, value, line));
    }

    fn end_of_headers(&mut self) {
        let current = self.current.as_mut().expect("in a part");
        current.in_headers = false;
        let disposition = current
            .headers
            .iter()
            .find(|(n, _, _)| n.eq_ignore_ascii_case("content-disposition"))
            .map(|(_, v, _)| v.clone());
        let Some(disposition) = disposition else {
            self.mp
                .fail("Multipart: Part missing Content-Disposition header.");
            return;
        };
        if let Err(rc) = content_disposition(disposition.as_bytes(), current, &mut self.mp.flags) {
            self.mp.fail(format!(
                "Multipart: Invalid Content-Disposition header ({rc})."
            ));
            return;
        }
        if current.name.is_empty() {
            self.mp
                .fail("Multipart: Content-Disposition header missing name field.");
        }
    }

    /// v3's `multipart_complete`, for a body that did not end in its final
    /// boundary.
    fn finish(&mut self) {
        if self.complete {
            return;
        }
        if self.boundaries == 0 {
            self.mp.fatal("Multipart: No boundaries found in payload.");
        } else {
            self.mp.fatal("Multipart: Final boundary missing.");
        }
    }
}

fn trim_start(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&c| c == b' ' || c == b'\t').count();
    &s[n..]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// RFC 2616's token characters, as v3's `is_token_char`.
fn is_token_char(c: u8) -> bool {
    c > 32 && c < 127 && !b"()<>@,;:\\\"/[]?=".contains(&c)
}

/// v3's `parse_content_disposition`: `form-data`, then `;`-separated `name`,
/// `filename` and `filename*` parameters, quoted or tokens. Anything else is
/// an error, numbered as v3 numbers it.
fn content_disposition(
    v: &[u8],
    part: &mut Current,
    flags: &mut MultipartFlags,
) -> Result<(), i32> {
    let skip = |p: &mut usize| {
        while *p < v.len() && (v[*p] == b' ' || v[*p] == b'\t') {
            *p += 1;
        }
    };
    if !v.starts_with(b"form-data") {
        return Err(-1);
    }
    let mut p = "form-data".len();
    skip(&mut p);
    if p == v.len() {
        return Ok(());
    }
    if v[p] != b';' {
        return Err(-2);
    }
    p += 1;
    loop {
        skip(&mut p);
        if p == v.len() {
            return Err(-3);
        }
        let start = p;
        while p < v.len() && v[p] != b'=' && v[p] != b' ' && v[p] != b'\t' {
            p += 1;
        }
        if p == v.len() {
            return Err(-4);
        }
        let param = &v[start..p];
        skip(&mut p);
        if p == v.len() || v[p] != b'=' {
            return Err(-13);
        }
        p += 1;
        skip(&mut p);
        if p == v.len() {
            return Err(-6);
        }
        if !matches!(param, b"name" | b"filename" | b"filename*") {
            return Err(-11);
        }
        let mut quote = 0u8;
        let value = if param == b"filename*" {
            ext_value(v, &mut p, flags)?
        } else if v[p] == b'"' || v[p] == b'\'' {
            quote = v[p];
            if quote == b'\'' {
                flags.invalid_quoting = true;
            }
            p += 1;
            let mut out = Vec::new();
            loop {
                let Some(&c) = v.get(p) else {
                    flags.invalid_quoting = true;
                    return Err(-15);
                };
                if c == b'\\' {
                    let Some(&n) = v.get(p + 1) else {
                        return Err(-8);
                    };
                    if n == quote || n == b'\\' {
                        out.push(n);
                        p += 2;
                    } else {
                        // Kept: IE sends paths with unescaped backslashes
                        out.push(c);
                        p += 1;
                    }
                    continue;
                }
                p += 1;
                if c == quote {
                    break;
                }
                out.push(c);
            }
            out
        } else {
            let s = p;
            while p < v.len() && is_token_char(v[p]) {
                p += 1;
            }
            v[s..p].to_vec()
        };
        if param != b"filename*" && quote != b'"' && value.contains(&b'\'') {
            flags.invalid_quoting = true;
        }
        match param {
            b"name" => {
                if !part.name.is_empty() {
                    flags.duplicate_part_header = true;
                    return Err(-14);
                }
                part.name = crate::bytes::text(&value);
            }
            b"filename" => {
                if part.filename.as_ref().is_some_and(|f| !f.is_empty()) {
                    flags.duplicate_part_header = true;
                    return Err(-15);
                }
                part.filename = Some(value);
            }
            _ => {
                if part.filename_star.as_ref().is_some_and(|f| !f.is_empty()) {
                    flags.duplicate_part_header = true;
                    return Err(-15);
                }
                part.filename_star = Some(value);
            }
        }
        skip(&mut p);
        if p == v.len() {
            return Ok(());
        }
        if v[p] != b';' {
            if p > 0 && (v[p - 1] == b'"' || v[p - 1] == b'\'') {
                flags.invalid_quoting = true;
            }
            return Err(-12);
        }
        p += 1;
    }
}

/// RFC 5987's ext-value for `filename*`: `charset'language'percent-encoded`,
/// decoded. Its syntax checked as v3 checks it.
fn ext_value(v: &[u8], p: &mut usize, flags: &mut MultipartFlags) -> Result<Vec<u8>, i32> {
    let start = *p;
    while *p < v.len() && (v[*p].is_ascii_alphanumeric() || b"!#$%&+-^_`{}~".contains(&v[*p])) {
        *p += 1;
    }
    if *p == start || v.get(*p) != Some(&b'\'') {
        return Err(-16);
    }
    *p += 1;
    match v[*p..].iter().position(|&c| c == b'\'') {
        Some(i) => *p += i + 1,
        None => {
            flags.invalid_quoting = true;
            return Err(-17);
        }
    }
    let mut out = Vec::new();
    while *p < v.len() && v[*p] != b';' {
        let c = v[*p];
        if c == b'%' {
            let hex = |c: Option<&u8>| c.and_then(|c| (*c as char).to_digit(16));
            match (hex(v.get(*p + 1)), hex(v.get(*p + 2))) {
                (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
                _ => return Err(-18),
            }
            *p += 3;
        } else if c.is_ascii_alphanumeric() || b"!#$&+-.^_`~".contains(&c) {
            out.push(c);
            *p += 1;
        } else {
            return Err(-19);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CT: &str = "multipart/form-data; boundary=XyZ";

    fn body(lines: &[&str], ending: &str) -> Vec<u8> {
        lines.join(ending).into_bytes()
    }

    fn ordinary() -> Vec<u8> {
        body(
            &[
                "--XyZ",
                "Content-Disposition: form-data; name=\"field1\"",
                "",
                "value1",
                "--XyZ",
                "Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"",
                "Content-Type: text/plain",
                "",
                "line one",
                "line two",
                "--XyZ--",
                "",
            ],
            "\r\n",
        )
    }

    #[test]
    fn a_browser_body_is_clean() {
        let mp = parse(CT, &ordinary());
        assert_eq!(mp.error, None);
        assert!(!mp.flags.strict_error(), "{:?}", mp.flags);
        assert_eq!(mp.parts.len(), 2);
        assert_eq!(mp.parts[0].name, "field1");
        assert_eq!(mp.parts[0].value, b"value1");
        assert_eq!(mp.parts[1].filename.as_deref(), Some("a.txt"));
        assert_eq!(mp.parts[1].value, b"line one\r\nline two");
        assert!(mp
            .part_headers
            .contains(&("upload".into(), "Content-Type: text/plain".into())));
    }

    #[test]
    fn binary_content_is_kept_byte_for_byte() {
        let mut b =
            b"--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\n\r\n"
                .to_vec();
        b.extend_from_slice(&[0xff, 0x00, 0xfe, b'\r', b'\n', 0x80]);
        b.extend_from_slice(b"\r\n--XyZ--\r\n");
        let mp = parse(CT, &b);
        assert_eq!(mp.error, None);
        assert_eq!(mp.parts[0].value, [0xff, 0x00, 0xfe, b'\r', b'\n', 0x80]);
    }

    #[test]
    fn lf_line_endings_are_flagged_and_still_parsed() {
        let mp = parse(
            CT,
            &body(
                &[
                    "--XyZ",
                    "Content-Disposition: form-data; name=\"k\"",
                    "",
                    "v",
                    "--XyZ--",
                    "",
                ],
                "\n",
            ),
        );
        assert!(mp.flags.lf_line && mp.flags.strict_error());
        assert_eq!(mp.parts[0].value, b"v");
    }

    #[test]
    fn the_boundary_checks() {
        let mut f = MultipartFlags::default();
        assert_eq!(
            boundary("multipart/form-data; boundary=\"b1\"", &mut f).unwrap(),
            "b1"
        );
        assert!(f.boundary_quoted);
        let mut f = MultipartFlags::default();
        assert_eq!(
            boundary("multipart/form-data; boundary = b1", &mut f).unwrap(),
            " b1"
        );
        assert!(f.boundary_whitespace);
        let mut f = MultipartFlags::default();
        assert_eq!(
            boundary("multipart/form-data boundary=b1", &mut f).unwrap(),
            "b1"
        );
        assert!(f.missing_semicolon);
        let mut f = MultipartFlags::default();
        assert_eq!(
            boundary("multipart/form-data; boundary=b1; charset=utf-8", &mut f).unwrap(),
            "b1"
        );
        assert!(!f.boundary_quoted && !f.boundary_whitespace && !f.missing_semicolon);
        for bad in [
            "multipart/form-data",
            "multipart/form-data; boundary=",
            "multipart/form-data; boundary=a; boundary=b",
            "multipart/form-data; BOUNDARY=a",
            "multipart/form-data; boundary=\"a",
            "multipart/form-data; boundary=a<b",
            "multipart/form-data; x=y; boundary=a",
        ] {
            assert!(
                boundary(bad, &mut MultipartFlags::default()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn data_before_and_after_are_flagged() {
        let mut b = b"preamble\r\n".to_vec();
        b.extend(ordinary());
        let mp = parse(CT, &b);
        assert!(mp.flags.data_before && mp.flags.strict_error());
        let mut b = ordinary();
        b.extend_from_slice(b"trailing");
        let mp = parse(CT, &b);
        assert!(mp.flags.data_after && mp.flags.strict_error());
    }

    #[test]
    fn a_missing_final_boundary_is_an_error() {
        let b = body(
            &[
                "--XyZ",
                "Content-Disposition: form-data; name=\"a\"",
                "",
                "b",
                "",
            ],
            "\r\n",
        );
        let mp = parse(CT, &b);
        assert_eq!(
            mp.error.as_deref(),
            Some("Multipart: Final boundary missing.")
        );
        assert!(mp.flags.strict_error());
        // ...but an unterminated final boundary at the very end is accepted
        let mut b = ordinary();
        b.truncate(b.len() - 2);
        assert_eq!(parse(CT, &b).error, None);
    }

    #[test]
    fn header_folding_and_its_invalid_form() {
        let b = body(
            &[
                "--XyZ",
                "Content-Disposition: form-data;",
                " name=\"a\"",
                "",
                "b",
                "--XyZ--",
                "",
            ],
            "\r\n",
        );
        let mp = parse(CT, &b);
        assert!(mp.flags.header_folding && !mp.flags.invalid_header_folding);
        assert_eq!(mp.parts[0].name, "a");
        let b = body(
            &[
                "--XyZ",
                "Content-Disposition: form-data;",
                "\x0bname=\"a\"",
                "",
                "b",
                "--XyZ--",
                "",
            ],
            "\r\n",
        );
        assert!(parse(CT, &b).flags.invalid_header_folding);
    }

    #[test]
    fn content_disposition_quoting_and_parameters() {
        let cd = |s: &str| {
            let mut c = Current::default();
            let mut f = MultipartFlags::default();
            let r = content_disposition(s.as_bytes(), &mut c, &mut f);
            (r, c, f)
        };
        let (r, c, f) = cd(r#"form-data; name="a\"b"; filename="C:\dir\x.txt""#);
        assert_eq!(r, Ok(()));
        assert_eq!(c.name, "a\"b");
        assert_eq!(c.filename.as_deref(), Some(&b"C:\\dir\\x.txt"[..]));
        assert!(!f.invalid_quoting);
        let (r, _, f) = cd("form-data; name='a'");
        assert_eq!(r, Ok(()));
        assert!(f.invalid_quoting);
        let (r, _, f) = cd(r#"form-data; name="a"#);
        assert_eq!(r, Err(-15));
        assert!(f.invalid_quoting);
        assert_eq!(cd(r#"form-data; name="a" filename="b""#).0, Err(-12));
        assert_eq!(cd(r#"form-data; name="a"; size=3"#).0, Err(-11));
        let (r, _, f) = cd(r#"form-data; name="a"; name="b""#);
        assert_eq!(r, Err(-14));
        assert!(f.duplicate_part_header);
        assert_eq!(cd("attachment; name=a").0, Err(-1));
        assert_eq!(cd("form-data name=a").0, Err(-2));
        assert_eq!(cd("form-data; name=a;").0, Err(-3));
        let (r, c, _) = cd("form-data; name=f; filename*=UTF-8''%E2%82%AC%20rates.txt");
        assert_eq!(r, Ok(()));
        assert_eq!(
            String::from_utf8(c.filename_star.unwrap()).unwrap(),
            "\u{20ac} rates.txt"
        );
        assert_eq!(cd("form-data; name=f; filename*=UTF-8''a%zz").0, Err(-18));
        assert_eq!(cd("form-data; name=f; filename*=UTF-8''a b").0, Err(-19));
    }

    #[test]
    fn a_part_without_a_name_is_dropped_and_flagged() {
        let b = body(
            &["--XyZ", "Content-Type: text/plain", "", "x", "--XyZ--", ""],
            "\r\n",
        );
        let mp = parse(CT, &b);
        assert!(mp.parts.is_empty());
        assert!(mp.flags.invalid_part);
        assert_eq!(
            mp.error.as_deref(),
            Some("Multipart: Part missing Content-Disposition header.")
        );
        assert_eq!(
            mp.part_headers,
            [(String::new(), "Content-Type: text/plain".into())]
        );
    }

    #[test]
    fn a_duplicate_part_header_is_flagged_and_dropped() {
        let b = body(
            &[
                "--XyZ",
                "Content-Disposition: form-data; name=\"a\"",
                "content-disposition: form-data; name=\"b\"",
                "",
                "x",
                "--XyZ--",
                "",
            ],
            "\r\n",
        );
        let mp = parse(CT, &b);
        assert!(mp.flags.duplicate_part_header && mp.flags.strict_error());
        assert_eq!(mp.parts[0].name, "a");
    }

    #[test]
    fn a_line_that_looks_like_another_boundary_is_noted() {
        let b = body(
            &[
                "--XyZ",
                "Content-Disposition: form-data; name=\"a\"",
                "",
                "--Other",
                "--XyZ--",
                "",
            ],
            "\r\n",
        );
        let mp = parse(CT, &b);
        // 1 for the stray line; the delimiter after it then reports 2, as v3
        // reports any delimiter after the first
        assert_ne!(mp.flags.unmatched_boundary, 0);
        assert!(!mp.flags.strict_error());
        assert_eq!(mp.parts[0].value, b"--Other");
    }

    #[test]
    fn extra_data_after_a_boundary_stops_parsing() {
        let b = body(
            &[
                "--XyZ",
                "Content-Disposition: form-data; name=\"a\"",
                "",
                "x",
                "--XyZ junk",
                "",
            ],
            "\r\n",
        );
        let mp = parse(CT, &b);
        assert!(mp.flags.fatal);
        assert_eq!(
            mp.error.as_deref(),
            Some("Multipart: Invalid boundary (extra data).")
        );
    }
}
