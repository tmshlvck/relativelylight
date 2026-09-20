//! `application/x-www-form-urlencoded` in one place — the codec both [`csrf`](crate::csrf) (finding
//! `_csrf` in a posted body) and [`crud::ui`](crate::crud::ui) (reading a query string, writing links)
//! need. Always compiled, dependency-free, `pub(crate)`.
//!
//! Percent-encoding is the whole of it: there is no need for a URL *parser* anywhere in this crate —
//! every link the UI emits is query-only and relative (`?page=2`), so it never has to build or split an
//! authority, path or fragment.

/// Decode one `application/x-www-form-urlencoded` component: `%XX` escapes, and `+` as a space.
pub(crate) fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Encode one component. Everything outside the unreserved set is escaped — including `[`/`]`, which
/// `filter[name]` keys contain, and `~`, which is unreserved but cheap to escape anyway.
pub(crate) fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => out.push(*b as char),
            b' ' => out.push('+'),
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Split a query string or form body into decoded `(key, value)` pairs, in order.
///
/// A `Vec`, not a map, on purpose: repeated keys are meaningful here — `ids=1&ids=2` is a bulk
/// selection, `filter[a]=x&filter[b]=y` are two conditions, and a multi-select sends one pair per
/// chosen option. A map would silently keep the last of each.
pub(crate) fn pairs(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(p), String::new()),
        })
        .collect()
}

/// Render `(key, value)` pairs as a query string — no leading `?`.
pub(crate) fn query(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_awkward_characters() {
        for raw in ["a b", "a+b", "100%", "sort=x&y", "filter[zone]", "ünïcode", "<script>"] {
            assert_eq!(decode(&encode(raw)), raw, "{raw}");
        }
    }

    #[test]
    fn repeated_keys_are_all_kept() {
        let got = pairs("ids=1&ids=2&q=a+b");
        assert_eq!(
            got,
            vec![
                ("ids".to_string(), "1".to_string()),
                ("ids".to_string(), "2".to_string()),
                ("q".to_string(), "a b".to_string()),
            ]
        );
    }

    #[test]
    fn a_bare_key_decodes_to_an_empty_value() {
        assert_eq!(pairs("all"), vec![("all".to_string(), String::new())]);
    }
}
