//! [`Thumbnailer`] — derived renderings of stored images (BLOBSTORE.md §6). Feature
//! `blob-thumbnail`.
//!
//! A thumbnail is a blob like any other: content-addressed, stored through the same backend,
//! subject to the same verify/fsck/purge machinery. There is no second storage mechanism and no
//! separate cache-invalidation story — [`blob_variant`](super::entity::variant) records which
//! derived blob answers which `(source, variant)` pair, and that row is a reference edge like any
//! other, so a thumbnail lives exactly as long as its source.
//!
//! Variants hang off **content**, not off a version: two documents with identical bytes share one
//! thumbnail, and renaming a file regenerates nothing.
//!
//! # Deliberately headless
//!
//! Nothing here needs `ui`. A batch job pre-generating thumbnails after a bulk import calls
//! [`Thumbnailer::ensure`] exactly as a page render would.

use std::io::Cursor;

use image::{DynamicImage, ImageFormat, ImageReader};

use super::{BlobBackend, BlobError, BlobId, BlobStore, WriteContext};

/// Generates and registers resized renderings of an image blob.
pub struct Thumbnailer {
    targets: Vec<(String, u32)>,
    max_source_bytes: u64,
    max_pixels: u64,
}

impl Default for Thumbnailer {
    fn default() -> Self {
        Self::new()
    }
}

impl Thumbnailer {
    /// Defaults: `thumb` 150 px, `mobile` 480 px, `desktop` 1024 px — each the **longest edge**,
    /// aspect ratio preserved.
    pub fn new() -> Self {
        Self {
            targets: vec![
                ("thumb".into(), 150),
                ("mobile".into(), 480),
                ("desktop".into(), 1024),
            ],
            max_source_bytes: 32 * 1024 * 1024,
            max_pixels: 64_000_000,
        }
    }

    /// Replace the set of variants. Each is `(name, longest edge in pixels)`; the name is free-form,
    /// so an app can add its own (`"og-image"`) and look it up the same way.
    pub fn targets<I, S>(mut self, targets: I) -> Self
    where
        I: IntoIterator<Item = (S, u32)>,
        S: Into<String>,
    {
        self.targets = targets.into_iter().map(|(n, px)| (n.into(), px)).collect();
        self
    }

    /// Refuse to decode a source larger than this. Default 32 MiB.
    pub fn max_source_bytes(mut self, n: u64) -> Self {
        self.max_source_bytes = n;
        self
    }

    /// Refuse to decode an image whose **pixel count** exceeds this, however small the file is.
    /// Default 64 megapixels.
    ///
    /// This is the decompression-bomb guard, and it is the reason the limit is in pixels rather than
    /// bytes: a few kilobytes of PNG can declare 50 000 × 50 000, which is 10 GB of RGBA once
    /// decoded. The byte cap above cannot see that coming; this one is checked from the header
    /// before any pixel buffer is allocated.
    pub fn max_pixels(mut self, n: u64) -> Self {
        self.max_pixels = n;
        self
    }

    /// Generate whichever configured variants don't already exist for `source`, store each through
    /// the same `store`, and register them.
    ///
    /// Returns every variant now available — generated **or pre-existing** — so a caller can use the
    /// result without caring which. A non-image source, or one this build can't decode, yields an
    /// empty list rather than an error: "there is no thumbnail for a text file" is an ordinary fact,
    /// not a failure.
    pub async fn ensure<B: BlobBackend>(
        &self,
        store: &BlobStore<B>,
        source: &BlobId,
        ctx: WriteContext<'_>,
    ) -> Result<Vec<(String, BlobId)>, BlobError> {
        let _ = ctx; // derived content is system-generated; nothing to attribute

        // What's already there, and what still needs making. Asking first means a page render that
        // hits this on every request costs one indexed lookup per variant, not a decode.
        let mut have: Vec<(String, BlobId)> = Vec::new();
        let mut wanted: Vec<(String, u32)> = Vec::new();
        for (name, px) in &self.targets {
            match store.variant(source, name).await? {
                Some(id) => have.push((name.clone(), id)),
                None => wanted.push((name.clone(), *px)),
            }
        }
        if wanted.is_empty() {
            return Ok(have);
        }

        let info = store.content_info(source).await?;
        if info.size_bytes as u64 > self.max_source_bytes || !info.mime_sniffed.starts_with("image/")
        {
            return Ok(have);
        }

        let bytes = store.read_content(source).await?;
        let Some(img) = self.decode(&bytes) else {
            // Undecodable content is not an error here: an app should not fail to render a page
            // because a file it was given isn't the image it claimed to be.
            return Ok(have);
        };

        for (name, px) in wanted {
            let Some(encoded) = encode(&img, px) else { continue };
            let derived = store.put_derived(&encoded[..]).await?;
            store.set_variant(source, &name, &derived).await?;
            have.push((name, derived));
        }
        Ok(have)
    }

    /// Decode with explicit limits. `None` for anything that isn't a decodable image, or that would
    /// cost more than the configured budget to decode.
    fn decode(&self, bytes: &[u8]) -> Option<DynamicImage> {
        let reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format().ok()?;

        // Check the declared dimensions *before* decoding. `image`'s own limits would also stop
        // this, but reading the header first means a bomb costs a header parse rather than an
        // allocation attempt that has to fail.
        let (w, h) = reader.into_dimensions().ok()?;
        if u64::from(w) * u64::from(h) > self.max_pixels {
            return None;
        }

        let mut reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format().ok()?;
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(w);
        limits.max_image_height = Some(h);
        limits.max_alloc = Some(self.max_pixels.saturating_mul(4));
        reader.limits(limits);
        reader.decode().ok()
    }
}

/// Resize to `px` on the longest edge and encode.
///
/// **JPEG when the source is opaque, PNG when it has alpha** — not WebP, which BLOBSTORE.md §6
/// originally named. `image`'s WebP encoder is **lossless only** (pure Rust, since 0.24.8), and a
/// lossless WebP of a photograph is routinely larger than the JPEG it was made from, which is the
/// opposite of what a thumbnail is for. Alpha can't survive JPEG at all, so transparency picks PNG.
/// Both are universally supported, which was the other half of the original reasoning.
///
/// Never upscales: a 40 px image asked for a 150 px `thumb` stays 40 px rather than being blown up
/// into a blurry one.
fn encode(img: &DynamicImage, px: u32) -> Option<Vec<u8>> {
    let (w, h) = (img.width(), img.height());
    let longest = w.max(h);
    let resized = if longest <= px { img.clone() } else { img.thumbnail(px, px) };

    let has_alpha = img.color().has_alpha();
    let mut out = Cursor::new(Vec::new());
    let format = if has_alpha { ImageFormat::Png } else { ImageFormat::Jpeg };

    // JPEG cannot carry an alpha channel and cannot encode 16-bit samples; normalise to something
    // each encoder actually accepts rather than letting it fail per source.
    let prepared =
        if has_alpha { DynamicImage::ImageRgba8(resized.to_rgba8()) } else { DynamicImage::ImageRgb8(resized.to_rgb8()) };

    prepared.write_to(&mut out, format).ok()?;
    Some(out.into_inner())
}
