//! A strict `multipart/form-data` reader for a **fully buffered** body.
//!
//! It exists so a file can be uploaded straight to the server — no JavaScript reading the file into
//! a text field first, which would assume UTF-8, inflate the body through percent-encoding, and put
//! a decoding failure somewhere the operator can't do anything about it.
//!
//! Buffered, not streaming, and deliberately so: the caller has the bytes already (its handler read
//! them), the token that authorises the write lives *in* the body, and a streaming parser would have
//! to buffer up to the token anyway. What it is not is a general-purpose implementation — it reads
//! the shape browsers actually post for a form this crate renders, and **refuses anything else**
//! rather than guessing:
//!
//! - no boundary in the content type, or an empty one → refused;
//! - a part with no `name` → refused;
//! - a body that ends without its closing `--boundary--` (a truncated upload) → refused;
//! - `Content-Transfer-Encoding` other than the identity browsers use → refused, because decoding it
//!   wrongly would corrupt a file silently.
//!
//! Everything here works on byte slices with checked indexing, so a malformed body is an `Err` and
//! never a panic. (`multer` is the crate to reach for if this ever needs to stream; that would be a
//! contained swap.)

/// One part of a posted form.
pub(crate) struct Part {
    pub(crate) name: String,
    /// Present when the part came from a file input — even when the file was empty, which is how an
    /// unused picker is told apart from one whose file had no bytes.
    pub(crate) filename: Option<String>,
    pub(crate) body: Vec<u8>,
}

/// The boundary from a `multipart/form-data` content type, or `None` if this isn't one.
pub(crate) fn boundary(content_type: &str) -> Option<String> {
    let (kind, params) = content_type.split_once(';')?;
    if !kind.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    for param in params.split(';') {
        let (key, value) = param.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("boundary") {
            let value = value.trim().trim_matches('"');
            return (!value.is_empty()).then(|| value.to_string());
        }
    }
    None
}

/// Split a buffered body into its parts.
pub(crate) fn parse(body: &[u8], boundary: &str) -> Result<Vec<Part>, String> {
    let delim = format!("--{boundary}").into_bytes();
    let mut out = Vec::new();

    // Skip the preamble: everything up to the first delimiter is ignorable by the spec.
    let mut at = find(body, &delim).ok_or("multipart body has no boundary")? + delim.len();
    loop {
        match body.get(at..at + 2) {
            Some(b"--") => return Ok(out), // closing delimiter: done
            Some(b"\r\n") => at += 2,
            // A final boundary with nothing after it (some clients omit the trailing CRLF).
            None => return Err("multipart body ends mid-boundary".into()),
            Some(_) => return Err("unexpected bytes after a multipart boundary".into()),
        }

        let rest = body.get(at..).ok_or("truncated multipart body")?;
        let headers_len = find(rest, b"\r\n\r\n").ok_or("a multipart part has no header block")?;
        let headers = std::str::from_utf8(&rest[..headers_len])
            .map_err(|_| "a multipart part has non-UTF-8 headers".to_string())?;
        let content_at = at + headers_len + 4;

        let (name, filename) = disposition(headers)?;
        if let Some(encoding) = header(headers, "content-transfer-encoding") {
            // Browsers send no encoding, or `binary`/`8bit`, all of which mean "as-is".
            if !matches!(encoding.to_ascii_lowercase().as_str(), "binary" | "8bit" | "7bit") {
                return Err(format!("unsupported content-transfer-encoding '{encoding}'"));
            }
        }

        // The part ends at the CRLF *before* the next delimiter — that CRLF belongs to the
        // delimiter, not to the content, which matters for a file whose last byte is a newline.
        let mut next = format!("\r\n--{boundary}").into_bytes();
        let content = body.get(content_at..).ok_or("truncated multipart part")?;
        let end = find(content, &next).ok_or("a multipart part is not terminated")?;
        out.push(Part { name, filename, body: content[..end].to_vec() });

        next.clear();
        at = content_at + end + 2 + delim.len();
    }
}

/// `name` and `filename` from a part's `Content-Disposition`.
fn disposition(headers: &str) -> Result<(String, Option<String>), String> {
    let value = header(headers, "content-disposition")
        .ok_or("a multipart part has no content-disposition")?;
    let mut name = None;
    let mut filename = None;
    for param in value.split(';').skip(1) {
        let Some((key, raw)) = param.split_once('=') else { continue };
        let raw = raw.trim().trim_matches('"').to_string();
        match key.trim().to_ascii_lowercase().as_str() {
            "name" => name = Some(raw),
            "filename" => filename = Some(raw),
            _ => {}
        }
    }
    Ok((name.ok_or("a multipart part has no name")?, filename))
}

/// One header's value, case-insensitively, from a part's header block.
fn header(headers: &str, want: &str) -> Option<String> {
    headers.split("\r\n").find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(want).then(|| value.trim().to_string())
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body shaped the way a browser posts the import dialog: the hidden fields, then the file.
    fn browser_body(file: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(b"------X\r\nContent-Disposition: form-data; name=\"_op\"\r\n\r\nimport\r\n");
        body.extend(b"------X\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\ntok3n\r\n");
        body.extend(
            b"------X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"rows.csv\"\r\n\
              Content-Type: text/csv\r\n\r\n",
        );
        body.extend(file);
        body.extend(b"\r\n------X--\r\n");
        body
    }

    #[test]
    fn reads_the_boundary_out_of_a_content_type() {
        assert_eq!(boundary("multipart/form-data; boundary=----X").as_deref(), Some("----X"));
        assert_eq!(boundary("Multipart/Form-Data; BOUNDARY=\"a b\"").as_deref(), Some("a b"));
        assert_eq!(boundary("application/x-www-form-urlencoded"), None);
        assert_eq!(boundary("multipart/form-data"), None, "no boundary is not a multipart we can read");
        assert_eq!(boundary("multipart/form-data; boundary="), None);
    }

    #[test]
    fn reads_the_fields_and_the_file() {
        let parts = parse(&browser_body(b"a,b\n1,2\n"), "----X").expect("parses");
        let names: Vec<&str> = parts.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["_op", "_csrf", "file"]);
        assert_eq!(parts[1].body, b"tok3n", "the token the write is authorised with");
        assert_eq!(parts[2].filename.as_deref(), Some("rows.csv"));
        assert_eq!(parts[2].body, b"a,b\n1,2\n", "the file's bytes, exactly");
    }

    #[test]
    fn a_files_trailing_newline_is_not_eaten_by_the_delimiter() {
        // The CRLF before a boundary belongs to the delimiter; a file's own last byte does not.
        for file in [&b"x\n"[..], b"x", b"x\r\n", b"\r\n"] {
            let parts = parse(&browser_body(file), "----X").expect("parses");
            assert_eq!(parts[2].body, file, "{file:?}");
        }
    }

    #[test]
    fn binary_content_survives_including_bytes_that_look_like_a_boundary() {
        let file = b"\x00\xff--not-the-boundary\r\n\x80\x81";
        let parts = parse(&browser_body(file), "----X").expect("parses");
        assert_eq!(parts[2].body, file);
    }

    #[test]
    fn an_empty_file_input_still_arrives_with_its_filename() {
        // How "the operator chose no file" is told apart from "the file was empty".
        let parts = parse(&browser_body(b""), "----X").expect("parses");
        assert_eq!(parts[2].body, b"");
        assert!(parts[2].filename.is_some());
    }

    #[test]
    fn malformed_bodies_are_refused_and_never_panic() {
        let good = browser_body(b"a,b\n");
        for (what, body) in [
            ("empty", Vec::new()),
            ("no boundary at all", b"just some bytes".to_vec()),
            ("truncated mid-file", good[..good.len() - 12].to_vec()),
            ("header block never ends", b"------X\r\nContent-Disposition: form-data".to_vec()),
            (
                "a part with no name",
                b"------X\r\nContent-Disposition: form-data; filename=\"x\"\r\n\r\nz\r\n------X--\r\n"
                    .to_vec(),
            ),
            (
                "an encoding we would have to decode",
                b"------X\r\nContent-Disposition: form-data; name=\"f\"\r\n\
                  Content-Transfer-Encoding: base64\r\n\r\nWg==\r\n------X--\r\n"
                    .to_vec(),
            ),
        ] {
            assert!(parse(&body, "----X").is_err(), "{what} must be refused");
        }
        // …and every prefix of a good body, which is what a dropped connection leaves.
        for cut in 0..good.len() {
            let _ = parse(&good[..cut], "----X");
        }
    }
}
