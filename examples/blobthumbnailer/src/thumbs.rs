//! Thumbnail generation — **an app's code, not the library's**.
//!
//! `blob` deliberately has no thumbnailer and no variant table. Sizes, formats and quality are
//! policy, and the same argument that puts ownership in the app's own table (BLOBSTORE.md §9) puts
//! this here too: the crate cannot know what an app wants, and a wrong guess is worse than none.
//!
//! What it costs the app is this file. What it buys is that a thumbnail is **an ordinary document**:
//! it gets a handle, it is referenced from the app's own table, and it is deleted and garbage
//! collected by exactly the same machinery as everything else. No second storage concept, no
//! reachability special case, no `Option` threaded through the store for derived content.

use std::io::Cursor;

use image::{DynamicImage, ImageFormat, ImageReader};
use relativelylight::blob::{BlobError, BlobStore, FsBackend, HandleId, PutMeta, WriteContext};

/// Refuse to decode an image whose **pixel count** exceeds this, however small the file is.
///
/// The decompression-bomb guard, and the reason it counts pixels rather than bytes: a few kilobytes
/// of PNG can declare 50 000 × 50 000, which is 10 GB of RGBA once decoded. A byte cap cannot see
/// that coming; this is read from the header before any pixel buffer is allocated.
const MAX_PIXELS: u64 = 64_000_000;

/// Generate a thumbnail for `source` and store it as its own document.
///
/// Returns `None` — not an error — when the content isn't a decodable image. A page listing
/// attachments must not fail to render because one of them is a text file.
pub async fn make(
    store: &BlobStore<FsBackend>,
    source: HandleId,
    longest_edge: u32,
) -> Result<Option<HandleId>, BlobError> {
    let head = store.head(source).await?;
    let Some(content) = &head.content else { return Ok(None) };
    if !content.mime_sniffed.starts_with("image/") || content.size_bytes > 32 * 1024 * 1024 {
        return Ok(None);
    }

    let bytes = store.read_content(&head.blob).await?;
    let Some(img) = decode(&bytes) else { return Ok(None) };
    let Some((encoded, ext)) = encode(&img, longest_edge) else { return Ok(None) };

    let name = format!("{}-thumb.{ext}", head.filename.rsplit_once('.').map(|(a, _)| a).unwrap_or(&head.filename));
    let handle = store
        .create(
            &encoded[..],
            PutMeta::new(name).mime(if ext == "png" { "image/png" } else { "image/jpeg" }),
            WriteContext::none(),
        )
        .await?;
    Ok(Some(handle))
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

/// Resize to `px` on the longest edge and encode.
///
/// **JPEG when the source is opaque, PNG when it has alpha.** Not WebP: `image`'s WebP encoder is
/// lossless-only, and a lossless WebP of a photograph is routinely larger than the JPEG it came
/// from — the opposite of what a thumbnail is for. Alpha cannot survive JPEG at all.
///
/// Never upscales: a 40 px image asked for 150 px stays 40 px rather than becoming a blurry, larger
/// file.
fn encode(img: &DynamicImage, px: u32) -> Option<(Vec<u8>, &'static str)> {
    let longest = img.width().max(img.height());
    let resized = if longest <= px { img.clone() } else { img.thumbnail(px, px) };

    let has_alpha = img.color().has_alpha();
    let prepared = if has_alpha {
        DynamicImage::ImageRgba8(resized.to_rgba8())
    } else {
        DynamicImage::ImageRgb8(resized.to_rgb8())
    };
    let format = if has_alpha { ImageFormat::Png } else { ImageFormat::Jpeg };

    let mut out = Cursor::new(Vec::new());
    prepared.write_to(&mut out, format).ok()?;
    Some((out.into_inner(), if has_alpha { "png" } else { "jpg" }))
}
