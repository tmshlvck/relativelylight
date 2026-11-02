//! Content-type sniffing and human-readable sizes.

/// How many leading bytes [`sniff_mime`] needs. An [`Upload`](super::Upload) reads this much of each
/// file ahead; an app sniffing a stored file reads this much of it.
pub const SNIFF_BYTES: usize = 1024;

/// The content type the **bytes** say, from magic numbers — for the handful of types a back office
/// actually sees.
///
/// Advisory, and deliberately small (FILES.md §5): it decides which tag [`Preview`](super::Preview)
/// picks and whether [`to_inline_response`](super::to_inline_response) will render inline, and is
/// what you compare against the uploader's claim. Anything it doesn't recognise is
/// `application/octet-stream`, which is always downloaded rather than rendered — the safe default.
pub fn sniff_mime(head: &[u8]) -> &'static str {
    match head {
        [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, ..] => "image/png",
        [0xff, 0xd8, 0xff, ..] => "image/jpeg",
        [b'G', b'I', b'F', b'8', ..] => "image/gif",
        [b'%', b'P', b'D', b'F', ..] => "application/pdf",
        [b'P', b'K', 0x03, 0x04, ..] => "application/zip",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "image/webp",
        [b'<', b's', b'v', b'g', ..] => "image/svg+xml",
        [] => "application/octet-stream",
        _ if is_text(&head[..head.len().min(SNIFF_BYTES)]) => "text/plain",
        _ => "application/octet-stream",
    }
}

/// UTF-8 without NUL bytes, allowing the prefix to end mid-character (it is cut at an arbitrary
/// byte). NUL is valid UTF-8 but no text file contains it, and plenty of binary formats do.
fn is_text(b: &[u8]) -> bool {
    if b.contains(&0) {
        return false;
    }
    match std::str::from_utf8(b) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none() && b.len() - e.valid_up_to() < 4,
    }
}

/// Bytes as something a person reads. Binary units, because that is what a file manager shows.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut n = bytes as f64;
    let mut i = 0;
    while n >= 1024.0 && i < UNITS.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{n:.1} {}", UNITS[i])
    }
}
