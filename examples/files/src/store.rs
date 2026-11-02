//! The app's storage: **one flat directory**. Not library code — this is the part `relativelylight`
//! leaves to the app, because a directory, a database column and an object store want different
//! answers to every question below. An app with a database would keep an index table instead of
//! listing the directory (docs/FILES.md §5).
//!
//! What it has to get right, and does here in a few lines each:
//!
//! - **Names never become paths outside the root.** [`clean`] makes a name from whatever a browser
//!   sent; a name from a URL is accepted only if it is already clean.
//! - **An upload is invisible until complete.** It is written to a hidden temporary file and only
//!   then linked under its name, so a listing never shows half a file and a failed upload leaves
//!   nothing behind.
//! - **A taken name is never overwritten.** The link fails if the name exists, and the next number
//!   is tried: `scan.pdf`, `scan (2).pdf`, …

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::fs;
use tokio::io::AsyncWriteExt;

/// A file as the listing shows it.
pub struct Entry {
    pub name: String,
    pub size: u64,
}

pub struct Store {
    root: PathBuf,
    seq: AtomicU64,
}

impl Store {
    pub async fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).await?;
        Ok(Self { root, seq: AtomicU64::new(0) })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path for a name from a request, or `None` if it isn't one this store could have made.
    pub fn path(&self, name: &str) -> Option<PathBuf> {
        (clean(name) == name).then(|| self.root.join(name))
    }

    /// Regular files, by name. Hidden files (the temporary uploads) and directories are skipped.
    pub async fn list(&self) -> io::Result<Vec<Entry>> {
        let mut out = Vec::new();
        let mut dir = fs::read_dir(&self.root).await?;
        while let Some(e) = dir.next_entry().await? {
            let Ok(name) = e.file_name().into_string() else { continue };
            // `file_type` doesn't follow symlinks, so a link to /etc/passwd isn't listed either.
            if !e.file_type().await?.is_file() || clean(&name) != name {
                continue;
            }
            out.push(Entry { name, size: e.metadata().await?.len() });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub async fn delete(&self, name: &str) -> io::Result<()> {
        let path = self.path(name).ok_or(io::ErrorKind::InvalidInput)?;
        fs::remove_file(path).await
    }

    /// Start writing an upload.
    pub async fn create(&self) -> io::Result<Pending> {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self.root.join(format!(".upload-{}-{n}", std::process::id()));
        let file = fs::File::create_new(&tmp).await?;
        Ok(Pending { tmp, file, root: self.root.clone() })
    }
}

/// An upload being written. [`commit`](Self::commit) it, or [`discard`](Self::discard) it.
pub struct Pending {
    tmp: PathBuf,
    file: fs::File,
    root: PathBuf,
}

impl Pending {
    pub async fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        self.file.write_all(chunk).await
    }

    /// Link the finished file under `wanted` (already [`clean`]ed), or the first free numbered
    /// variant of it. Returns the name it got.
    pub async fn commit(self, wanted: &str) -> io::Result<String> {
        self.file.sync_all().await?;
        for n in 1..1000 {
            let name = numbered(wanted, n);
            // `hard_link` refuses an existing target: the check and the claim are one step, so two
            // uploads of `scan.pdf` at the same moment can't both get the name.
            match fs::hard_link(&self.tmp, self.root.join(&name)).await {
                Ok(()) => {
                    fs::remove_file(&self.tmp).await?;
                    return Ok(name);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    self.discard().await;
                    return Err(e);
                }
            }
        }
        self.discard().await;
        Err(io::ErrorKind::AlreadyExists.into())
    }

    pub async fn discard(self) {
        let _ = fs::remove_file(&self.tmp).await;
    }
}

/// `n = 1` is the name itself; then `scan (2).pdf`, `scan (3).pdf`, …
fn numbered(name: &str, n: u32) -> String {
    if n == 1 {
        return name.to_owned();
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} ({n}).{ext}"),
        _ => format!("{name} ({n})"),
    }
}

/// A safe file name from anything a browser sends: the last path component, no control characters,
/// no leading dot (hidden files are this store's own), not too long. A name is valid exactly when
/// cleaning leaves it unchanged — which is how [`Store::path`] checks a name from a URL.
pub fn clean(raw: &str) -> String {
    let last = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    let name: String = last.chars().filter(|c| !c.is_control()).collect();
    let name = name.trim().trim_start_matches('.').trim_end();
    // Cut at a character boundary; a long name loses its middle rather than its extension.
    let name = if name.len() > 200 {
        let (stem, ext) =
            name.rsplit_once('.').filter(|(_, e)| e.len() <= 10).unwrap_or((name, ""));
        let mut cut = 190.min(stem.len());
        while !stem.is_char_boundary(cut) {
            cut -= 1;
        }
        if ext.is_empty() {
            stem[..cut].to_owned()
        } else {
            format!("{}.{ext}", &stem[..cut])
        }
    } else {
        name.to_owned()
    };
    if name.is_empty() {
        "file".into()
    } else {
        name
    }
}
