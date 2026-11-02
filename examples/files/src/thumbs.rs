//! Thumbnails, made **on request** into a cache — **an app's code, not the library's**.
//!
//! Nothing is generated at upload. The first request for a thumbnail decodes the image and writes
//! `<cache>/<sha256>-<px>.png`; every later one is a file read. Keyed by the *content*, so the cache
//! is never stale — a file replaced under the same name has a new hash — and never needs to follow a
//! rename or a delete: it can be wiped at any time and rebuilds itself.
//!
//! This app has no index table, so it hashes the image on each request (cheap next to decoding it).
//! An app that stores the hash at upload puts it in the thumbnail URL instead, and serves the result
//! as `immutable`.

use std::io::Cursor;
use std::path::PathBuf;

use image::{DynamicImage, ImageFormat, ImageReader};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

/// Images larger than this get no thumbnail: decoding is the expensive part, and a cap keeps one
/// request from tying up a blocking thread for long.
const MAX_SOURCE: u64 = 32 * 1024 * 1024;

/// Whether a type gets a thumbnail — by what the bytes are, not the name. Not SVG: it is a document,
/// and the `image` crate doesn't read it anyway.
pub fn raster(mime: &str) -> bool {
    matches!(mime, "image/png" | "image/jpeg" | "image/gif" | "image/webp")
}

pub struct Cache {
    dir: PathBuf,
    px: u32,
    /// Decodes at once. A page of 50 new images asks for 50 thumbnails together; without a bound each
    /// is a blocking thread and up to `MAX_PIXELS × 4` bytes of memory.
    decoding: Semaphore,
}

impl Cache {
    pub async fn open(dir: impl Into<PathBuf>, px: u32) -> std::io::Result<Self> {
        let dir = dir.into();
        tokio::fs::create_dir_all(&dir).await?;
        Ok(Self { dir, px, decoding: Semaphore::new(2) })
    }

    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// The thumbnail for the image at `source` and its hash (the ETag), or `None` when it is too large
    /// or doesn't decode — an ordinary outcome, not an error.
    pub async fn get(&self, source: &std::path::Path) -> Option<(Vec<u8>, String)> {
        if tokio::fs::metadata(source).await.ok()?.len() > MAX_SOURCE {
            return None;
        }
        let bytes = tokio::fs::read(source).await.ok()?;
        let hash = hex(&Sha256::digest(&bytes));
        let cached = self.dir.join(format!("{hash}-{}.png", self.px));
        if let Ok(png) = tokio::fs::read(&cached).await {
            return Some((png, hash));
        }
        let _permit = self.decoding.acquire().await.ok()?;
        let px = self.px;
        let png = tokio::task::spawn_blocking(move || png(&bytes, px)).await.ok()??;
        // Through a temporary name, so a concurrent request never reads half a PNG. Two requests
        // racing for the same thumbnail both write it; the content is identical, so either wins.
        let tmp = self.dir.join(format!(".{hash}-{px}.{}", std::process::id()));
        if tokio::fs::write(&tmp, &png).await.is_ok() {
            let _ = tokio::fs::rename(&tmp, &cached).await;
        }
        println!("thumbnail {} ({} bytes)", cached.display(), png.len());
        Some((png, hash))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Refuse to decode an image whose **pixel count** exceeds this, however small the file is.
///
/// The decompression-bomb guard, and the reason it counts pixels rather than bytes: a few kilobytes
/// of PNG can declare 50 000 × 50 000, which is 10 GB of RGBA once decoded. A byte cap cannot see
/// that coming; this is read from the header before any pixel buffer is allocated.
const MAX_PIXELS: u64 = 64_000_000;

/// A PNG at most `px` on its longest edge, or `None` when `bytes` isn't a decodable image — an
/// ordinary outcome for a PDF, not an error. CPU-bound: call it from `spawn_blocking`.
///
/// PNG because it keeps transparency, and because the output is never the uploaded bytes: an image
/// that is also something else (a polyglot) goes out re-encoded. Never upscales.
fn png(bytes: &[u8], px: u32) -> Option<Vec<u8>> {
    let img = decode(bytes)?;
    let small = if img.width().max(img.height()) <= px { img } else { img.thumbnail(px, px) };
    let mut out = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(small.to_rgba8()).write_to(&mut out, ImageFormat::Png).ok()?;
    Some(out.into_inner())
}

fn decode(bytes: &[u8]) -> Option<DynamicImage> {
    let probe = ImageReader::new(Cursor::new(bytes)).with_guessed_format().ok()?;
    let (w, h) = probe.into_dimensions().ok()?;
    if u64::from(w) * u64::from(h) > MAX_PIXELS {
        return None;
    }
    let mut reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format().ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(w);
    limits.max_image_height = Some(h);
    limits.max_alloc = Some(MAX_PIXELS.saturating_mul(4));
    reader.limits(limits);
    reader.decode().ok()
}
