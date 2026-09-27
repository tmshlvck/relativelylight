//! Tests for `blob`, written the way `auth/security_tests.rs` is: the properties that would be
//! *silently* wrong get the coverage, with a positive control beside each so a negative can't pass
//! vacuously. They run against a fresh in-memory SQLite database and a real temp directory, so what
//! is under test is the shipped behaviour and not a re-implementation.
//!
//! What each group pins:
//!
//! - **identity** — dedup shares content but never metadata, which is the defect the three-table
//!   split exists to prevent (BLOBSTORE.md §3.1).
//! - **the chain** — appending never rewrites a previous version, `seq` never renumbers, and every
//!   older version stays readable.
//! - **integrity** — tampered content is refused with no bytes handed back, and `verify` finds it
//!   without being asked to serve it.
//! - **constraints** — the database, not this crate's care, is what stops content disappearing from
//!   under a version.
//! - **erasure** — content dies, history doesn't (§4.8).
//! - **fsck** — missing is an alarm, orphaned is routine, and neither is guessed at inside the
//!   grace period.
//! - **audit** — every committed write and every served read reaches the observer, reads included.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sea_orm::{ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter};

use super::entity::{content, handle as handle_entity, version};
use super::*;
use crate::authz::Operation;
use crate::observe::{WriteEvent, WriteObserver};

// ===================== Fixture =====================

struct Fx {
    store: BlobStore<FsBackend>,
    db: DatabaseConnection,
    root: tempfile::TempDir,
}

impl Fx {
    async fn new() -> Fx {
        Fx::with(|s| s).await
    }

    async fn with(configure: impl FnOnce(BlobStore<FsBackend>) -> BlobStore<FsBackend>) -> Fx {
        let root = tempfile::tempdir().expect("tempdir");
        let backend = FsBackend::new(root.path());
        backend.init().await.expect("init");
        let db = Database::connect("sqlite::memory:").await.expect("connect");
        migrate(&db).await.expect("migrate");
        let store = configure(BlobStore::new(backend, db.clone()));
        Fx { store, db, root }
    }

    async fn put(&self, name: &str, body: &[u8]) -> HandleId {
        self.store
            .create(body, PutMeta::new(name).by("alice"), WriteContext::none())
            .await
            .expect("create")
    }

    /// The on-disk path of a blob, for the tests that corrupt or remove content behind the store's
    /// back — the only way to reach the states a crash or a bad disk produces.
    fn path_of(&self, id: &BlobId) -> std::path::PathBuf {
        let (a, b) = id.fanout();
        self.root.path().join(a).join(b).join(id.as_str())
    }

    /// Files left in the staging directory. Should be zero after every completed call, successful
    /// or not — staging litter is the failure mode a streaming write path introduces.
    fn staged_files(&self) -> usize {
        std::fs::read_dir(self.root.path().join("tmp")).map(|d| d.count()).unwrap_or(0)
    }

    async fn content_rows(&self) -> usize {
        content::Entity::find().all(&self.db).await.expect("query").len()
    }

    async fn version_rows(&self, h: HandleId) -> usize {
        version::Entity::find()
            .filter(version::Column::HandleId.eq(h.uuid()))
            .all(&self.db)
            .await
            .expect("query")
            .len()
    }
}

/// Read a version's content all the way into memory — fine for the small fixtures here, and the
/// reason `BlobHandle` keeps `into_bytes` alongside the stream it actually hands out.
async fn read_bytes(fx: &Fx, v: VersionId) -> Vec<u8> {
    fx.store.read(v, WriteContext::none()).await.expect("read").into_bytes().await.expect("collect")
}

/// One observed event, reduced to what these tests assert about.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    op: Operation,
    entity: String,
    key: Option<String>,
    version: Option<i64>,
}

/// Records every event, so a test can assert what the audit trail would have contained.
#[derive(Default)]
struct Spy {
    seen: Mutex<Vec<Seen>>,
}

#[async_trait]
impl WriteObserver for Spy {
    async fn on_write(&self, ev: &WriteEvent<'_>) {
        self.seen.lock().unwrap().push(Seen {
            op: ev.op,
            entity: ev.entity.to_owned(),
            key: ev.key.clone(),
            version: ev.version,
        });
    }
}

impl Spy {
    fn ops(&self) -> Vec<Operation> {
        self.seen.lock().unwrap().iter().map(|s| s.op).collect()
    }
}

// ===================== Identity =====================

#[tokio::test]
async fn a_round_trip_returns_exactly_what_went_in() {
    let fx = Fx::new().await;
    let h = fx.put("greeting.txt", b"hello world").await;

    let head = fx.store.head(h).await.expect("head");
    assert_eq!(head.seq, 1);
    assert_eq!(head.filename, "greeting.txt");
    assert_eq!(head.created_by.as_deref(), Some("alice"));
    assert_eq!(head.prev, None, "the first version has no predecessor");
    assert_eq!(head.size_bytes(), 11);

    let got = fx.store.read(head.id, WriteContext::none()).await.expect("read");
    assert_eq!(got.into_bytes().await.unwrap(), b"hello world");
}

#[tokio::test]
async fn identical_content_is_stored_once_but_never_shares_its_metadata() {
    // The whole reason for three tables (BLOBSTORE.md §3.1): keyed by digest alone, the second
    // upload's filename and attribution would be silently discarded in favour of the first's.
    let fx = Fx::new().await;
    let a = fx
        .store
        .create(&b"the same bytes"[..], PutMeta::new("alice-copy.pdf").by("alice"), WriteContext::none())
        .await
        .expect("create a");
    let b = fx
        .store
        .create(&b"the same bytes"[..], PutMeta::new("bob-copy.pdf").by("bob"), WriteContext::none())
        .await
        .expect("create b");

    assert_ne!(a, b, "two uploads are two documents even with identical content");
    assert_eq!(fx.content_rows().await, 1, "the bytes are stored once");

    let (va, vb) = (fx.store.head(a).await.unwrap(), fx.store.head(b).await.unwrap());
    assert_eq!(va.blob, vb.blob, "…and both versions point at that one content row");
    assert_eq!(va.filename, "alice-copy.pdf");
    assert_eq!(vb.filename, "bob-copy.pdf");
    assert_eq!(va.created_by.as_deref(), Some("alice"));
    assert_eq!(vb.created_by.as_deref(), Some("bob"));
}

#[tokio::test]
async fn a_handle_survives_every_edit_of_its_content() {
    let fx = Fx::new().await;
    let h = fx.put("doc.txt", b"v1").await;
    for body in [&b"v2"[..], b"v3"] {
        fx.store
            .put_version(h, body, PutMeta::new("doc.txt").by("alice"), WriteContext::none())
            .await
            .expect("put_version");
    }
    assert_eq!(fx.store.head(h).await.unwrap().seq, 3);
    // The point of the design: the app's foreign key never had to change.
    assert_eq!(fx.store.versions(h).await.unwrap()[0].handle, h);
}

// ===================== The chain =====================

#[tokio::test]
async fn appending_a_version_leaves_every_earlier_one_untouched_and_readable() {
    let fx = Fx::new().await;
    let h = fx.put("report.txt", b"draft").await;
    let first = fx.store.head(h).await.unwrap();

    let second = fx
        .store
        .put_version(h, &b"final"[..], PutMeta::new("report.txt").by("bob"), WriteContext::none())
        .await
        .expect("put_version");

    let chain = fx.store.versions(h).await.unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!((chain[0].seq, chain[1].seq), (1, 2));
    assert_eq!(chain[1].prev, Some(first.id), "the new version points back");
    assert_eq!(chain[0].prev, None, "…and the old one was not rewritten to point forward");
    assert_eq!(fx.store.head(h).await.unwrap().id, second, "the head moved");

    // Both are still there, byte for byte. A version chain that loses its history isn't one.
    assert_eq!(read_bytes(&fx, first.id).await, b"draft");
    assert_eq!(read_bytes(&fx, second).await, b"final");
    assert_eq!(chain[0].created_by.as_deref(), Some("alice"));
    assert_eq!(chain[1].created_by.as_deref(), Some("bob"), "each version keeps its own author");
}

#[tokio::test]
async fn amend_makes_a_new_version_over_the_same_content_without_storing_it_twice() {
    let fx = Fx::new().await;
    let h = fx.put("MISPELLED.txt", b"unchanged bytes").await;
    let before = fx.store.head(h).await.unwrap();

    fx.store
        .amend(h, PutMeta::new("corrected.txt").by("bob"), WriteContext::none())
        .await
        .expect("amend");

    let after = fx.store.head(h).await.unwrap();
    assert_eq!(after.seq, 2, "a rename is a version, not a silent edit");
    assert_eq!(after.filename, "corrected.txt");
    assert_eq!(after.blob, before.blob, "…over the very same content");
    assert_eq!(fx.content_rows().await, 1, "no second copy of the bytes");
    assert_eq!(
        fx.store.versions(h).await.unwrap()[0].filename,
        "MISPELLED.txt",
        "and the old name is still on the record"
    );
}

#[tokio::test]
async fn a_handle_with_no_versions_cannot_be_appended_to_or_read() {
    let fx = Fx::new().await;
    let ghost = HandleId::new();
    assert!(matches!(fx.store.head(ghost).await, Err(BlobError::NotFound(_))));
    assert!(matches!(
        fx.store.amend(ghost, PutMeta::new("x"), WriteContext::none()).await,
        Err(BlobError::NotFound(_))
    ));
}

// ===================== Integrity =====================

#[tokio::test]
async fn content_that_no_longer_hashes_to_its_id_is_refused_and_no_bytes_are_handed_back() {
    let fx = Fx::new().await;
    let h = fx.put("invoice.pdf", b"the real invoice").await;
    let v = fx.store.head(h).await.unwrap();

    // Control: it reads fine before anyone touches the disk.
    assert_eq!(read_bytes(&fx, v.id).await, b"the real invoice");

    let blob = v.blob.clone().unwrap();
    tokio::fs::write(fx.path_of(&blob), b"the forged invoice!").await.expect("tamper");

    match fx.store.read(v.id, WriteContext::none()).await {
        Err(BlobError::Corrupt { expected, .. }) => assert_eq!(expected, blob),
        other => panic!("tampered content must be refused, got {other:?}"),
    }
}

#[tokio::test]
async fn verify_finds_corruption_and_loss_without_serving_anything() {
    let fx = Fx::new().await;
    let good = fx.put("good.txt", b"intact").await;
    let bad = fx.put("bad.txt", b"will be corrupted").await;
    let gone = fx.put("gone.txt", b"will be deleted").await;

    let bad_blob = fx.store.head(bad).await.unwrap().blob.unwrap();
    let gone_blob = fx.store.head(gone).await.unwrap().blob.unwrap();
    tokio::fs::write(fx.path_of(&bad_blob), b"corrupted").await.unwrap();
    tokio::fs::remove_file(fx.path_of(&gone_blob)).await.unwrap();

    let report = fx.store.verify(VerifyOptions { oldest: None }).await.expect("verify");
    assert_eq!(report.checked, 3);
    assert_eq!(report.corrupt, vec![bad_blob]);
    assert_eq!(report.missing, vec![gone_blob]);
    let good_blob = fx.store.head(good).await.unwrap().blob.unwrap();
    assert!(!report.corrupt.contains(&good_blob), "control: the intact blob is not flagged");
}

#[tokio::test]
async fn an_upload_over_the_limit_is_refused_while_streaming() {
    let fx = Fx::with(|s| s.max_bytes(16)).await;
    let err = fx
        .store
        .create(&b"considerably more than sixteen bytes"[..], PutMeta::new("big"), WriteContext::none())
        .await;
    assert!(matches!(err, Err(BlobError::TooLarge { limit: 16 })));
    assert_eq!(fx.content_rows().await, 0, "nothing was indexed");
    assert_eq!(fx.staged_files(), 0, "and the partial upload was cleaned up, not left in tmp/");
}

#[tokio::test]
async fn oversized_metadata_is_refused_before_anything_is_written() {
    let fx = Fx::new().await;
    let huge = serde_json::json!({ "note": "x".repeat(MAX_METADATA_BYTES) });
    let err = fx
        .store
        .create(&b"body"[..], PutMeta::new("f.txt").metadata(huge), WriteContext::none())
        .await;
    assert!(matches!(err, Err(BlobError::TooLarge { .. })));
    assert_eq!(fx.content_rows().await, 0, "the check runs before the bytes are stored");

    // Control: a reasonable one goes through and comes back.
    let h = fx
        .store
        .create(
            &b"body"[..],
            PutMeta::new("f.txt").metadata(serde_json::json!({"scanner": "fujitsu"})),
            WriteContext::none(),
        )
        .await
        .expect("create");
    assert_eq!(
        fx.store.head(h).await.unwrap().metadata,
        Some(serde_json::json!({"scanner": "fujitsu"}))
    );
}

// ===================== Constraints =====================

#[tokio::test]
async fn the_database_refuses_to_delete_content_a_version_still_points_at() {
    // Not a test of `purge`'s care — a test that the constraint is really there, so a bug in the
    // reachability sweep cannot orphan a version.
    let fx = Fx::new().await;
    let h = fx.put("doc.txt", b"referenced").await;
    let blob = fx.store.head(h).await.unwrap().blob.unwrap();

    let err = content::Entity::delete_by_id(blob.to_string()).exec(&fx.db).await;
    assert!(err.is_err(), "deleting referenced content must violate the foreign key");
    assert_eq!(fx.content_rows().await, 1, "and the row is still there");
}

#[tokio::test]
async fn deleting_a_handle_takes_its_whole_chain_with_it() {
    let fx = Fx::new().await;
    let h = fx.put("doc.txt", b"v1").await;
    fx.store
        .put_version(h, &b"v2"[..], PutMeta::new("doc.txt"), WriteContext::none())
        .await
        .unwrap();
    let bystander = fx.put("other.txt", b"untouched").await;
    assert_eq!(fx.version_rows(h).await, 2, "control");

    fx.store.delete_handle(h, WriteContext::none()).await.expect("delete_handle");

    assert_eq!(fx.version_rows(h).await, 0, "the versions cascade");
    assert!(handle_entity::Entity::find_by_id(h.uuid()).one(&fx.db).await.unwrap().is_none());
    assert_eq!(fx.version_rows(bystander).await, 1, "and only that handle's");
    assert!(fx.store.head(bystander).await.is_ok());
}

// ===================== Erasure (§4.8) =====================

#[tokio::test]
async fn erasing_destroys_the_content_and_keeps_the_record() {
    let fx = Fx::new().await;
    let h = fx.put("personal.pdf", b"subject data").await;
    fx.store
        .put_version(h, &b"later revision"[..], PutMeta::new("personal.pdf"), WriteContext::none())
        .await
        .unwrap();
    let first = fx.store.versions(h).await.unwrap()[0].id;

    fx.store.erase(first, WriteContext::none()).await.expect("erase");

    let chain = fx.store.versions(h).await.unwrap();
    assert_eq!(chain.len(), 2, "the entry stays in the history");
    assert_eq!(chain[0].seq, 1, "and is not renumbered — a gap must read as a gap");
    assert!(chain[0].is_erased());
    assert!(chain[0].purged_at.is_some());
    assert_eq!(chain[0].filename, "personal.pdf", "the record still says what it was");
    assert_eq!(chain[1].prev, Some(first), "the chain is not broken");

    // `Erased`, not `NotFound`: the difference matters to whatever renders this.
    assert!(matches!(
        fx.store.read(first, WriteContext::none()).await,
        Err(BlobError::Erased(v)) if v == first
    ));
    assert!(fx.store.read(chain[1].id, WriteContext::none()).await.is_ok(), "control: the other version still reads");
}

#[tokio::test]
async fn purge_frees_erased_content_but_spares_bytes_another_document_shares() {
    let fx = Fx::new().await;
    // Two documents, identical content — the case where a careless purge destroys someone else's
    // file.
    let mine = fx
        .store
        .create(&b"shared bytes"[..], PutMeta::new("mine.pdf"), WriteContext::none())
        .await
        .unwrap();
    let theirs = fx
        .store
        .create(&b"shared bytes"[..], PutMeta::new("theirs.pdf"), WriteContext::none())
        .await
        .unwrap();
    let lonely = fx.put("lonely.txt", b"referenced once").await;
    let shared_blob = fx.store.head(mine).await.unwrap().blob.unwrap();
    let lonely_blob = fx.store.head(lonely).await.unwrap().blob.unwrap();

    fx.store.erase(fx.store.head(mine).await.unwrap().id, WriteContext::none()).await.unwrap();
    fx.store.erase(fx.store.head(lonely).await.unwrap().id, WriteContext::none()).await.unwrap();

    let report = fx.store.purge(None).await.expect("purge");
    assert!(report.content_deleted.contains(&lonely_blob), "content nothing references is collected");
    assert!(
        !report.content_deleted.contains(&shared_blob),
        "content another document still points at is not"
    );
    assert!(fx.store.read(fx.store.head(theirs).await.unwrap().id, WriteContext::none()).await.is_ok());
    assert!(!fx.path_of(&lonely_blob).exists(), "and the bytes really went");
}

#[tokio::test]
async fn purge_without_a_checker_never_touches_a_handle() {
    let fx = Fx::new().await;
    let h = fx.put("doc.txt", b"still here").await;
    let report = fx.store.purge(None).await.expect("purge");
    assert!(report.handles_deleted.is_empty(), "the safe default disowns nothing");
    assert!(fx.store.head(h).await.is_ok());
}

#[tokio::test]
async fn purge_with_a_checker_drops_the_handles_the_app_disowns() {
    struct Disowns(HandleId);
    #[async_trait]
    impl HandleReference for Disowns {
        async fn is_referenced(&self, h: HandleId) -> bool {
            h != self.0
        }
    }

    let fx = Fx::new().await;
    let dropped = fx.put("orphan.txt", b"nothing points here").await;
    let kept = fx.put("kept.txt", b"still referenced").await;

    let report = fx.store.purge(Some(&Disowns(dropped))).await.expect("purge");
    assert_eq!(report.handles_deleted, vec![dropped]);
    assert!(fx.store.head(dropped).await.is_err());
    assert!(fx.store.head(kept).await.is_ok(), "control: the referenced one survives");
}

// ===================== fsck =====================

#[tokio::test]
async fn fsck_calls_a_missing_blob_an_alarm_and_a_young_orphan_nothing_at_all() {
    let fx = Fx::new().await;
    let h = fx.put("doc.txt", b"indexed and present").await;
    let blob = fx.store.head(h).await.unwrap().blob.unwrap();

    // An orphan exactly as a crash between `write` and the index insert would leave one.
    let orphan = BlobId::of(b"written but never indexed");
    fx.store
        .backend()
        .write(&orphan, Box::pin(std::io::Cursor::new(b"written but never indexed".to_vec())))
        .await
        .unwrap();

    let clean = fx.store.fsck(FsckOptions::default(), None).await.expect("fsck");
    assert!(clean.missing.is_empty(), "control: nothing is missing yet");
    assert!(clean.orphaned.is_empty(), "a fresh orphan is inside the grace period");
    assert_eq!(clean.orphans_too_young, 1, "…and is counted, not ignored");

    // Past the grace period it becomes collectable — but only when asked.
    let opts = FsckOptions { orphan_grace_secs: -1, collect_orphans: false };
    let seen = fx.store.fsck(opts, None).await.expect("fsck");
    assert_eq!(seen.orphaned, vec![orphan.clone()]);
    assert_eq!(seen.orphans_collected, 0, "reporting is not collecting");
    assert!(fx.store.backend().exists(&orphan).await.unwrap());

    let collected = fx
        .store
        .fsck(FsckOptions { orphan_grace_secs: -1, collect_orphans: true }, None)
        .await
        .expect("fsck");
    assert_eq!(collected.orphans_collected, 1);
    assert!(!fx.store.backend().exists(&orphan).await.unwrap());

    // And the other direction: bytes vanishing under a live row is the alarm.
    tokio::fs::remove_file(fx.path_of(&blob)).await.unwrap();
    let broken = fx.store.fsck(FsckOptions::default(), None).await.expect("fsck");
    assert_eq!(broken.missing, vec![blob]);
}

#[tokio::test]
async fn fsck_reports_a_head_pointing_at_nothing() {
    // `head_version_id` is the one column with no foreign key behind it (the table cycle), so this
    // check is what stands in for the constraint.
    let fx = Fx::new().await;
    let h = fx.put("doc.txt", b"body").await;
    assert!(
        fx.store.fsck(FsckOptions::default(), None).await.unwrap().dangling_heads.is_empty(),
        "control: a healthy head"
    );

    handle_entity::Entity::update_many()
        .col_expr(handle_entity::Column::HeadVersionId, sea_orm::sea_query::Expr::value(Some(999_999i64)))
        .filter(handle_entity::Column::Id.eq(h.uuid()))
        .exec(&fx.db)
        .await
        .unwrap();

    assert_eq!(fx.store.fsck(FsckOptions::default(), None).await.unwrap().dangling_heads, vec![h]);
}

// ===================== Variants and backup =====================

#[tokio::test]
async fn a_variant_hangs_off_content_so_two_documents_with_the_same_bytes_share_it() {
    let fx = Fx::new().await;
    let a = fx.store.create(&b"an image"[..], PutMeta::new("a.png"), WriteContext::none()).await.unwrap();
    let b = fx.store.create(&b"an image"[..], PutMeta::new("b.png"), WriteContext::none()).await.unwrap();
    let source = fx.store.head(a).await.unwrap().blob.unwrap();

    assert_eq!(fx.store.variant(&source, "thumb").await.unwrap(), None, "control: none yet");
    let derived = fx.store.put_derived(&b"a thumbnail"[..]).await.unwrap();
    fx.store.set_variant(&source, "thumb", &derived).await.unwrap();

    assert_eq!(fx.store.variant(&source, "thumb").await.unwrap(), Some(derived.clone()));
    let b_source = fx.store.head(b).await.unwrap().blob.unwrap();
    assert_eq!(
        fx.store.variant(&b_source, "thumb").await.unwrap(),
        Some(derived.clone()),
        "the other document gets it for free — a rendering belongs to bytes, not to a document"
    );

    // A variant is a reference edge: purge must not collect the thumbnail.
    let report = fx.store.purge(None).await.unwrap();
    assert!(!report.content_deleted.contains(&derived));
}

#[tokio::test]
async fn backup_copies_verified_content_and_skips_what_is_already_there() {
    let fx = Fx::new().await;
    fx.put("one.txt", b"first").await;
    fx.put("two.txt", b"second").await;

    let dest_dir = tempfile::tempdir().unwrap();
    let dest = FsBackend::new(dest_dir.path());
    dest.init().await.unwrap();

    let first = fx.store.backup_to(&dest).await.expect("backup");
    assert_eq!(first.copied.len(), 2);
    assert!(first.failed.is_empty());

    let again = fx.store.backup_to(&dest).await.expect("backup");
    assert!(again.copied.is_empty(), "a second run copies nothing");
    assert_eq!(again.already_present.len(), 2);
}

// ===================== Audit (§4.7) =====================

#[tokio::test]
async fn every_write_and_every_served_read_reaches_the_observer() {
    let spy = Arc::new(Spy::default());
    let fx = Fx::with(|s| s.on_write(spy.clone())).await;

    let h = fx.put("doc.txt", b"v1").await;
    let v2 = fx
        .store
        .put_version(h, &b"v2"[..], PutMeta::new("doc.txt"), WriteContext::none())
        .await
        .unwrap();
    fx.store.read(v2, WriteContext::none()).await.unwrap();
    fx.store.delete_handle(h, WriteContext::none()).await.unwrap();

    assert_eq!(
        spy.ops(),
        vec![Operation::Create, Operation::Update, Operation::Read, Operation::Delete],
        "a download is an auditable event, not just a write"
    );

    let seen = spy.seen.lock().unwrap();
    let read = seen.iter().find(|s| s.op == Operation::Read).unwrap();
    assert_eq!(read.entity, "blob_version");
    assert_eq!(read.version, Some(v2.0), "the event names which version was served");
}

#[tokio::test]
async fn a_refused_write_fires_nothing() {
    // An audit trail that records attempts as though they were writes is worse than none.
    let spy = Arc::new(Spy::default());
    let fx = Fx::with(|s| s.max_bytes(4).on_write(spy.clone())).await;

    assert!(fx
        .store
        .create(&b"far too long"[..], PutMeta::new("big.txt"), WriteContext::none())
        .await
        .is_err());
    assert!(spy.ops().is_empty(), "nothing committed, nothing observed");

    // Control: a write that does commit is observed.
    fx.store.create(&b"ok"[..], PutMeta::new("small.txt"), WriteContext::none()).await.unwrap();
    assert_eq!(spy.ops(), vec![Operation::Create]);
}

#[tokio::test]
async fn with_no_observer_registered_nothing_is_attributed_and_nothing_breaks() {
    // The §8 app: no observer, no auth, no crud. `WriteContext::none()` must be a complete answer.
    let fx = Fx::new().await;
    let h = fx.put("doc.txt", b"body").await;
    assert!(fx.store.read(fx.store.head(h).await.unwrap().id, WriteContext::none()).await.is_ok());
}

#[tokio::test]
async fn a_handle_cannot_have_two_versions_with_the_same_sequence_number() {
    // Pins the constraint, not the code path that respects it: two concurrent `put_version` calls
    // can both read head.seq = 1 and both try to write version 2. Without the unique index the
    // loser silently becomes a second version 2 and the chain forks in a way nothing detects.
    use sea_orm::{ActiveModelTrait, Set};
    let fx = Fx::new().await;
    let h = fx.put("doc.txt", b"v1").await;
    let first = fx.store.head(h).await.unwrap();

    let duplicate = version::ActiveModel {
        handle_id: Set(h.uuid()),
        seq: Set(first.seq), // the number version 1 already holds
        prev_version_id: Set(None),
        blob_id: Set(first.blob.map(|b| b.to_string())),
        filename: Set("forked.txt".into()),
        mime_declared: Set(String::new()),
        created_by: Set(None),
        created_at: Set(0),
        purged_at: Set(None),
        metadata: Set(None),
        ..Default::default()
    }
    .insert(&fx.db)
    .await;

    assert!(duplicate.is_err(), "a duplicate (handle, seq) must violate the unique index");
    assert_eq!(fx.version_rows(h).await, 1);

    // Control: the next sequence number is accepted, so the index isn't refusing everything.
    fx.store
        .put_version(h, &b"v2"[..], PutMeta::new("doc.txt"), WriteContext::none())
        .await
        .expect("the real append still works");
    assert_eq!(fx.version_rows(h).await, 2);
}

#[tokio::test]
async fn regenerating_a_variant_replaces_the_old_mapping_rather_than_duplicating_it() {
    let fx = Fx::new().await;
    let h = fx.put("photo.png", b"an image").await;
    let source = fx.store.head(h).await.unwrap().blob.unwrap();

    let first = fx.store.put_derived(&b"thumbnail v1"[..]).await.unwrap();
    fx.store.set_variant(&source, "thumb", &first).await.unwrap();
    let second = fx.store.put_derived(&b"thumbnail v2"[..]).await.unwrap();
    fx.store.set_variant(&source, "thumb", &second).await.expect("re-registering must upsert");

    assert_eq!(fx.store.variant(&source, "thumb").await.unwrap(), Some(second));
    // The superseded thumbnail is now unreferenced, and collectable like any other content.
    let report = fx.store.purge(None).await.unwrap();
    assert!(report.content_deleted.contains(&first));
}

#[tokio::test]
async fn content_larger_than_one_chunk_streams_through_intact() {
    // Exercises the multi-chunk path end to end: a PNG header followed by enough data to span
    // several reads, which is also the case where a buffering implementation would show up as
    // memory rather than as a failure.
    let fx = Fx::new().await;
    let mut body = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    body.extend((0..400_000u32).map(|i| (i % 251) as u8));

    let h = fx.store.create(&body[..], PutMeta::new("scan.png"), WriteContext::none()).await.unwrap();
    let head = fx.store.head(h).await.unwrap();

    assert_eq!(head.size_bytes(), body.len() as i64);
    assert_eq!(
        head.content.as_ref().unwrap().mime_sniffed,
        "image/png",
        "the type comes from the retained prefix, not from holding the whole file"
    );
    assert_eq!(read_bytes(&fx, head.id).await, body, "every byte survives the round trip");
    assert_eq!(fx.staged_files(), 0, "the staged file was committed, not abandoned");
}

#[tokio::test]
async fn a_read_hands_back_a_stream_that_was_verified_in_full_first() {
    // The two-pass read (BLOBSTORE.md §4.3): the digest is checked over the whole blob *before* a
    // reader is handed out, so nothing a caller can forward to a client is ever unverified.
    let fx = Fx::new().await;
    let mut body = vec![b'%', b'P', b'D', b'F'];
    body.extend(std::iter::repeat_n(b'x', 300_000));
    let h = fx.store.create(&body[..], PutMeta::new("big.pdf"), WriteContext::none()).await.unwrap();
    let v = fx.store.head(h).await.unwrap();

    assert_eq!(read_bytes(&fx, v.id).await.len(), body.len(), "control: it reads");

    // Corrupt a byte deep inside — past anything a prefix check would catch.
    let blob = v.blob.clone().unwrap();
    let mut tampered = body.clone();
    tampered[250_000] = b'y';
    tokio::fs::write(fx.path_of(&blob), &tampered).await.unwrap();

    assert!(
        matches!(fx.store.read(v.id, WriteContext::none()).await, Err(BlobError::Corrupt { .. })),
        "a change anywhere in the content must be caught before a reader is returned"
    );
}

#[tokio::test]
async fn a_backend_write_failure_leaves_nothing_staged_and_nothing_indexed() {
    // A reader that dies part-way, as a client hanging up mid-upload would look.
    struct Fails(usize);
    impl tokio::io::AsyncRead for Fails {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.0 == 0 {
                return std::task::Poll::Ready(Err(std::io::Error::other("connection reset")));
            }
            let n = self.0.min(buf.remaining());
            buf.put_slice(&vec![b'a'; n]);
            self.0 -= n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    let fx = Fx::new().await;
    let err = fx.store.create(Fails(100_000), PutMeta::new("truncated.bin"), WriteContext::none()).await;

    assert!(err.is_err(), "a reader that fails mid-stream must fail the upload");
    assert_eq!(fx.content_rows().await, 0, "nothing was indexed");
    assert_eq!(fx.staged_files(), 0, "and the half-written staging file went with it");
}
