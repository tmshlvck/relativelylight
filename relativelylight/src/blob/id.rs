//! The three identities, as types that can't be confused for one another — see
//! [BLOBSTORE.md §3.1](../../../docs/BLOBSTORE.md). A digest, a handle and a version are all "the id
//! of a file" in casual speech, and passing one where another belongs is the mistake the split
//! exists to prevent; making them distinct types means the compiler catches it rather than a
//! `NotFound` at runtime.

use std::fmt;
use std::str::FromStr;

use super::BlobError;

/// A content address: the lowercase hex SHA-256 of the bytes, exactly 64 characters.
///
/// **Never client-supplied.** It is computed while streaming an upload, or read back out of the
/// index. The parsing constructors exist for the one place a string does arrive from outside — an
/// admin URL naming a blob to verify — and they reject anything that is not 64 lowercase hex
/// characters, so a path traversal (`../../etc/passwd`) cannot reach a backend that builds a file
/// path out of one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobId(String);

impl BlobId {
    /// The digest of `bytes`, computed here so no caller has to know which hash this is.
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        Self(hex(&h.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The two-level fan-out a filesystem backend stores under: `("ab", "cd")` for `abcd…`.
    /// Here rather than in [`FsBackend`](super::FsBackend) because any backend that wants to avoid a
    /// million entries in one directory wants the same split, and because it is only safe on an id
    /// that has been validated — which, by construction, this one has.
    pub fn fanout(&self) -> (&str, &str) {
        (&self.0[0..2], &self.0[2..4])
    }

    pub(crate) fn from_digest(d: impl AsRef<[u8]>) -> Self {
        Self(hex(d.as_ref()))
    }
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl FromStr for BlobId {
    type Err = BlobError;

    fn from_str(s: &str) -> Result<Self, BlobError> {
        let ok = s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(BlobError::BadId(s.to_owned()))
        }
    }
}

impl TryFrom<&str> for BlobId {
    type Error = BlobError;
    fn try_from(s: &str) -> Result<Self, BlobError> {
        s.parse()
    }
}

impl TryFrom<String> for BlobId {
    type Error = BlobError;
    fn try_from(s: String) -> Result<Self, BlobError> {
        s.as_str().parse()
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The stable identity of a document: what an app's own tables hold a foreign key to, unchanged for
/// the life of the document however many versions it acquires (BLOBSTORE.md §9).
///
/// A **UUIDv7** ([RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html)) — time-ordered, so inserts
/// land at the end of a B-tree index instead of scattering across it the way v4 does, while staying
/// generatable app-side without a round trip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HandleId(pub uuid::Uuid);

impl HandleId {
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7())
    }

    pub fn uuid(&self) -> uuid::Uuid {
        self.0
    }
}

impl Default for HandleId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<uuid::Uuid> for HandleId {
    fn from(u: uuid::Uuid) -> Self {
        Self(u)
    }
}

impl FromStr for HandleId {
    type Err = BlobError;
    fn from_str(s: &str) -> Result<Self, BlobError> {
        uuid::Uuid::parse_str(s).map(Self).map_err(|_| BlobError::BadId(s.to_owned()))
    }
}

impl fmt::Display for HandleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One entry in a handle's version chain. Assigned by the database, so it is opaque and monotonic
/// but says nothing about order *within* a handle — that is `seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionId(pub i64);

impl From<i64> for VersionId {
    fn from(i: i64) -> Self {
        Self(i)
    }
}

impl fmt::Display for VersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_round_trips_and_fans_out() {
        let id = BlobId::of(b"hello");
        assert_eq!(id.as_str().len(), 64);
        // SHA-256("hello"), so the constructor is pinned to the hash the spec names, not merely to
        // "some 64 hex characters".
        assert_eq!(id.as_str(), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        assert_eq!(id.fanout(), ("2c", "f2"));
        assert_eq!(id.as_str().parse::<BlobId>().unwrap(), id);
    }

    #[test]
    fn a_malformed_digest_is_refused_rather_than_reaching_a_backend() {
        for bad in [
            "",
            "abc",
            "../../../etc/passwd",
            "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824", // uppercase
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b982",  // 63
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b98244", // 65
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b982g",
        ] {
            assert!(bad.parse::<BlobId>().is_err(), "{bad:?} must not parse as a digest");
        }
    }

    #[test]
    fn handles_are_time_ordered() {
        let (a, b) = (HandleId::new(), HandleId::new());
        assert!(a < b || a.to_string() < b.to_string(), "v7 ids must sort by creation time");
        assert_eq!(a.to_string().parse::<HandleId>().unwrap(), a);
    }
}
