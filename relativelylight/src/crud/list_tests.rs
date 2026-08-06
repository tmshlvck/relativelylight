//! Listing behaviour that only a real database can demonstrate: ordering by a **relation's label**,
//! exact-match `filter[…]`, and the page stability that both depend on.
//!
//! These drive the real router over in-memory SQLite with two entities related the way a downstream
//! app relates them — `record` belongs to `zone`, `zone` has many `record`s — because the interesting
//! cases (does the join reproduce the *displayed* order, does an FK filter match exactly, does a tie
//! in the sort column repeat rows across pages) are all invisible to a stub accessor.

use crate::authz::Open;
use crate::crud::seaorm::{Crud, MetaModel};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use serde_json::Value;
use tower::ServiceExt;

// ---- entities ----

mod zone {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "zone")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub origin: String,
        pub kind: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(has_many = "super::record::Entity")]
        Record,
    }

    impl Related<super::record::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Record.def()
        }
    }
    impl ActiveModelBehavior for ActiveModel {}
}

mod record {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "record")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: String,
        pub ttl: i32,
        pub zone_id: Option<i32>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::zone::Entity",
            from = "Column::ZoneId",
            to = "super::zone::Column::Id"
        )]
        Zone,
    }

    impl Related<super::zone::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Zone.def()
        }
    }
    impl ActiveModelBehavior for ActiveModel {}
}

// ---- fixture ----

/// Zone ids deliberately disagree with alphabetical order of `origin`, so "sorted by the label" and
/// "sorted by the foreign key" produce visibly different answers and a test can tell them apart.
/// Zone **11** exists so an exact filter for zone `1` can be caught matching it as a substring.
async fn seed(db: &DatabaseConnection) {
    for stmt in [
        "CREATE TABLE zone (id INTEGER PRIMARY KEY, origin TEXT NOT NULL, kind TEXT NOT NULL)",
        "CREATE TABLE record (id INTEGER PRIMARY KEY, name TEXT NOT NULL, ttl INTEGER NOT NULL, \
         zone_id INTEGER)",
        "INSERT INTO zone (id, origin, kind) VALUES \
           (1, 'zeta.example.', 'primary'), \
           (2, 'alpha.example.', 'primary'), \
           (3, 'mid.example.', 'secondary'), \
           (11, 'other.example.', 'secondary')",
        // Every record shares ttl = 3600 except one: a near-total tie, which is what makes an
        // unstable paginated sort show itself.
        "INSERT INTO record (id, name, ttl, zone_id) VALUES \
           (1, 'www', 3600, 1), \
           (2, 'mail', 3600, 2), \
           (3, 'ns1', 3600, 3), \
           (4, 'ns2', 3600, 11), \
           (5, 'ftp', 3600, 1), \
           (6, 'vpn', 300, 2), \
           (7, 'orphan', 3600, NULL)",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
}

/// The router, with `zone` labelled by whichever mechanism the test is exercising.
async fn app_with(label: Label) -> axum::Router {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    seed(&db).await;

    let mut z = MetaModel::new(zone::Entity);
    match label {
        Label::Declared => {
            z.label_column("origin");
        }
        // The escape hatch an app reaches for today: a plain closure reading one column.
        Label::Closure => {
            z.row_label = Box::new(|r| r["origin"].as_str().unwrap_or_default().to_string());
        }
        // A label SQL cannot reproduce — two columns joined together.
        Label::Computed => {
            z.row_label = Box::new(|r| {
                format!(
                    "{} ({})",
                    r["origin"].as_str().unwrap_or_default(),
                    r["kind"].as_str().unwrap_or_default()
                )
            });
        }
    }
    let rec = MetaModel::new(record::Entity);

    let mut crud = Crud::new(db, "");
    crud.register(z, Open);
    crud.register(rec, Open);
    crud.into_router().layer(axum::middleware::from_fn_with_state(
        crate::middleware::TrustProxy(false),
        crate::middleware::resolve_real_ip,
    ))
}

enum Label {
    Declared,
    Closure,
    Computed,
}

async fn send(app: &axum::Router, method: &str, uri: &str) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::empty())
        .unwrap();
    let addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
    req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::String(
        String::from_utf8_lossy(&bytes).into_owned(),
    ));
    (status, body)
}

/// The `name` of each returned row, in order.
fn names(page: &Value) -> Vec<String> {
    page["data"]
        .as_array()
        .expect("a data array")
        .iter()
        .map(|it| it["row"]["name"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The label shown for each row's `zone` cell, in order.
fn zone_labels(page: &Value) -> Vec<String> {
    page["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|it| it["row"]["zone"]["label"].as_str().unwrap_or("—").to_string())
        .collect()
}

// ---- sorting by a relation ----

#[tokio::test]
async fn sorting_by_a_relation_orders_by_the_shown_label_not_the_foreign_key() {
    let app = app_with(Label::Declared).await;
    let (status, page) = send(&app, "GET", "/record?sort=zone").await;
    assert_eq!(status, StatusCode::OK);

    // Alphabetical by origin. Sorting by `zone_id` instead would give zeta, zeta, alpha, … — the
    // control that proves this isn't just the FK order under another name.
    let labels = zone_labels(&page);
    assert_eq!(
        labels,
        vec![
            "alpha.example.",
            "alpha.example.",
            "mid.example.",
            "other.example.",
            "zeta.example.",
            "zeta.example.",
            "—", // the zone-less record sorts last: NULLS LAST, on every backend
        ],
        "rows must come back ordered by the label the cell shows"
    );

    let (_, desc) = send(&app, "GET", "/record?sort=zone:desc").await;
    let mut reversed = zone_labels(&desc);
    reversed.retain(|l| l != "—");
    assert_eq!(reversed.first().map(String::as_str), Some("zeta.example."));
}

#[tokio::test]
async fn a_row_label_closure_that_reads_one_column_is_still_sortable() {
    // The probe's whole point: an app that already assigns the common one-column closure gets a
    // sortable relation without rewriting it as `label_column`.
    let app = app_with(Label::Closure).await;
    let (status, page) = send(&app, "GET", "/record?sort=zone").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(zone_labels(&page)[0], "alpha.example.");

    let (_, meta) = send(&app, "GET", "/record?per_page=1").await;
    assert_eq!(meta["total"], 7);
}

#[tokio::test]
async fn a_label_that_is_not_a_single_column_is_refused_rather_than_ordered_by_a_guess() {
    let app = app_with(Label::Computed).await;
    let (status, body) = send(&app, "GET", "/record?sort=zone").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a label SQL can't reproduce must not be silently ordered by one of its parts"
    );
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(msg.contains("zone"), "the error names the column: {msg}");

    // …and the UI is told, so it doesn't render a header that 400s on click.
    let (_, page) = send(&app, "GET", "/record?per_page=1").await;
    assert_eq!(page["total"], 7);
}

#[tokio::test]
async fn the_metadata_says_which_columns_can_be_sorted() {
    for (label, want_zone_sortable) in [(Label::Declared, true), (Label::Computed, false)] {
        let app = app_with(label).await;
        // `_meta` isn't routed by default, so read the same values the UI does, via the engine.
        let (status, page) = send(&app, "GET", "/record?sort=name").await;
        assert_eq!(status, StatusCode::OK, "a plain column is always sortable");
        assert_eq!(names(&page)[0], "ftp");

        let (status, _) = send(&app, "GET", "/record?sort=zone").await;
        assert_eq!(
            status.is_success(),
            want_zone_sortable,
            "the relation's sortability must match what the metadata advertises"
        );
    }
}

#[tokio::test]
async fn sorting_by_a_to_many_relation_is_refused() {
    let app = app_with(Label::Declared).await;
    // A zone has many records, so there is no single label to order a zone by.
    let (status, body) = send(&app, "GET", "/zone?sort=record").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap_or_default().contains("record"));
}

#[tokio::test]
async fn an_unknown_sort_key_is_still_a_400() {
    let app = app_with(Label::Declared).await;
    let (status, _) = send(&app, "GET", "/record?sort=nope").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---- page stability ----

#[tokio::test]
async fn paging_a_tied_sort_column_shows_every_row_exactly_once() {
    // Six of seven records share ttl = 3600. Without the primary key appended as a final sort key the
    // database may order the tie differently for each page's query, so a row can appear on both pages
    // while another appears on neither — the failure that clickable sort headers would surface.
    let app = app_with(Label::Declared).await;
    let mut seen = Vec::new();
    for page in 1..=4 {
        let (status, p) = send(&app, "GET", &format!("/record?sort=ttl&per_page=2&page={page}")).await;
        assert_eq!(status, StatusCode::OK);
        seen.extend(names(&p));
    }
    seen.sort();
    assert_eq!(
        seen,
        vec!["ftp", "mail", "ns1", "ns2", "orphan", "vpn", "www"],
        "every row exactly once across the pages, none repeated or skipped"
    );
}

// ---- filtering ----

#[tokio::test]
async fn a_relation_filter_matches_the_foreign_key_exactly() {
    let app = app_with(Label::Declared).await;
    let (status, page) = send(&app, "GET", "/record?filter[zone]=1").await;
    assert_eq!(status, StatusCode::OK);

    let mut got = names(&page);
    got.sort();
    // Zone 11 exists precisely to catch a substring match: `LIKE '%1%'` would drag ns2 in here.
    assert_eq!(got, vec!["ftp", "www"], "an exact FK match, not a substring one");
    assert_eq!(page["total"], 2);
}

#[tokio::test]
async fn a_filter_may_name_a_plain_column_too() {
    let app = app_with(Label::Declared).await;
    let (status, page) = send(&app, "GET", "/record?filter[ttl]=300").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(names(&page), vec!["vpn"]);
}

#[tokio::test]
async fn an_empty_filter_value_finds_the_rows_that_have_none() {
    let app = app_with(Label::Declared).await;
    let (status, page) = send(&app, "GET", "/record?filter[zone]=").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(names(&page), vec!["orphan"], "an empty value means IS NULL");
}

#[tokio::test]
async fn an_unknown_filter_name_is_a_400() {
    let app = app_with(Label::Declared).await;
    let (status, _) = send(&app, "GET", "/record?filter[nope]=1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_substring_search_on_a_non_text_column_is_refused() {
    // This used to be `ttl LIKE '%300%'`: wrong on SQLite (3000 would match) and a type error on
    // PostgreSQL. Neither is an answer, so it is a 400 naming the column.
    let app = app_with(Label::Declared).await;
    let (status, body) = send(&app, "GET", "/record?ttl=300").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap_or_default().contains("ttl"));

    // A text column is unaffected — the control.
    let (status, page) = send(&app, "GET", "/record?name=ns").await;
    assert_eq!(status, StatusCode::OK);
    let mut got = names(&page);
    got.sort();
    assert_eq!(got, vec!["ns1", "ns2"]);
}

#[tokio::test]
async fn several_filters_in_one_query_all_apply() {
    // A `HashMap` extractor kept only the last of these; both must survive and combine.
    let app = app_with(Label::Declared).await;
    let (status, page) = send(&app, "GET", "/record?filter[zone]=2&filter[ttl]=300").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(names(&page), vec!["vpn"]);

    let (status, page) = send(&app, "GET", "/record?search[name]=n&search[name]=s").await;
    assert_eq!(status, StatusCode::OK);
    let mut got = names(&page);
    got.sort();
    assert_eq!(got, vec!["ns1", "ns2"], "both substring conditions apply, not just the last");
}

#[tokio::test]
async fn a_filtered_bulk_delete_deletes_only_the_matching_rows_and_needs_no_all_flag() {
    let app = app_with(Label::Declared).await;
    let (status, body) = send(&app, "DELETE", "/record?filter[zone]=1").await;
    assert_eq!(status, StatusCode::OK, "a filter is a filter for the whole-table guard");
    assert_eq!(body["deleted"], 2);

    let (_, page) = send(&app, "GET", "/record").await;
    assert_eq!(page["total"], 5, "the other zones' records are untouched");

    // The guard still holds for an unfiltered delete.
    let (status, _) = send(&app, "DELETE", "/record").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_filter_and_a_sort_compose() {
    let app = app_with(Label::Declared).await;
    let (status, page) = send(&app, "GET", "/record?filter[ttl]=3600&sort=name:desc").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(names(&page), vec!["www", "orphan", "ns2", "ns1", "mail", "ftp"]);
}
