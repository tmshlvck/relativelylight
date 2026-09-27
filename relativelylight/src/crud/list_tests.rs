//! Listing behaviour that only a real database can demonstrate: ordering by a **relation's label**,
//! exact-match `filter[…]`, and the page stability that both depend on.
//!
//! These drive the real SeaORM backend over in-memory SQLite with two entities related the way a
//! downstream app relates them — `record` belongs to `zone`, `zone` has many `record`s — because the
//! interesting cases (does the join reproduce the *displayed* order, does an FK filter match exactly,
//! does a tie in the sort column repeat rows across pages) are all invisible to a stub accessor.
//!
//! They call `Engine::list` with the `ViewState` a URL parses to, which is exactly what the UI does:
//! there is no HTTP layer in between any more, so a failure here is a failure in the backend rather
//! than in a wire format.

use crate::authz::Open;
use crate::crud::engine::{Engine, ListQuery, Page, Result};
use crate::crud::seaorm::{Crud, MetaModel};
use crate::crud::ui::ViewState;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};

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

/// A live engine, with `zone` labelled by whichever mechanism the test is exercising.
async fn engine_with(label: Label) -> Engine {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    seed(&db).await;

    let mut z = MetaModel::new(zone::Entity);
    match label {
        Label::Declared => {
            z.label_column("origin");
        }
        // The escape hatch an app reaches for: a plain closure reading one column.
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

    let mut crud = Crud::new(db);
    crud.register(z, Open);
    crud.register(MetaModel::new(record::Entity), Open);
    crud.into_engine()
}

enum Label {
    Declared,
    Closure,
    Computed,
}

/// List through the same path a rendered table takes: a query string → `ViewState` → `ListQuery`.
async fn list(engine: &Engine, slug: &str, query: &str) -> Result<Page> {
    let state = ViewState::from_query(query);
    engine.list(slug, &state.to_list_query(25), false).await
}

/// The `name` of each returned row, in order.
fn names(page: &Page) -> Vec<String> {
    page.data
        .iter()
        .map(|it| it.row.as_ref().unwrap()["name"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The label shown for each row's `zone` cell, in order.
fn zone_labels(page: &Page) -> Vec<String> {
    page.data
        .iter()
        .map(|it| {
            it.row.as_ref().unwrap()["zone"]["label"].as_str().unwrap_or("—").to_string()
        })
        .collect()
}

// ---- sorting by a relation ----

#[tokio::test]
async fn sorting_by_a_relation_orders_by_the_shown_label_not_the_foreign_key() {
    let e = engine_with(Label::Declared).await;
    let page = list(&e, "record", "sort=zone").await.expect("lists");

    // Alphabetical by origin. Sorting by `zone_id` instead would give zeta, zeta, alpha, … — the
    // control that proves this isn't just the FK order under another name.
    assert_eq!(
        zone_labels(&page),
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

    let desc = list(&e, "record", "sort=zone:desc").await.expect("lists");
    let mut reversed = zone_labels(&desc);
    reversed.retain(|l| l != "—");
    assert_eq!(reversed.first().map(String::as_str), Some("zeta.example."));
}

#[tokio::test]
async fn a_row_label_closure_that_reads_one_column_is_still_sortable() {
    // The probe's whole point: an app that already assigns the common one-column closure gets a
    // sortable relation without rewriting it as `label_column`.
    let e = engine_with(Label::Closure).await;
    let page = list(&e, "record", "sort=zone").await.expect("lists");
    assert_eq!(zone_labels(&page)[0], "alpha.example.");
    assert_eq!(page.total, 7);
}

#[tokio::test]
async fn a_label_that_is_not_a_single_column_is_refused_rather_than_ordered_by_a_guess() {
    let e = engine_with(Label::Computed).await;
    let err = list(&e, "record", "sort=zone")
        .await
        .expect_err("a label SQL can't reproduce must not be silently ordered by one of its parts");
    assert!(err.to_string().contains("zone"), "the error names the column: {err}");

    // Unsorted listing is unaffected — the control.
    assert_eq!(list(&e, "record", "").await.expect("lists").total, 7);
}

#[tokio::test]
async fn the_columns_say_which_ones_can_be_sorted() {
    for (label, zone_sortable) in [(Label::Declared, true), (Label::Computed, false)] {
        let e = engine_with(label).await;
        // What the UI reads to decide whether a header is a link — and what the backend then honours.
        let cols = e.columns("record").expect("registered");
        let advertised = cols
            .iter()
            .find_map(|c| match c {
                crate::crud::Column::Relation { name, sortable, .. } if name == "zone" => {
                    Some(*sortable)
                }
                _ => None,
            })
            .expect("a zone relation");
        assert_eq!(advertised, zone_sortable);
        assert_eq!(
            list(&e, "record", "sort=zone").await.is_ok(),
            zone_sortable,
            "a header the UI renders as a link must be one the backend will sort by"
        );

        let by_column = list(&e, "record", "sort=name").await.expect("a plain column always sorts");
        assert_eq!(names(&by_column)[0], "ftp");
    }
}

#[tokio::test]
async fn sorting_by_a_to_many_relation_is_refused() {
    let e = engine_with(Label::Declared).await;
    // A zone has many records, so there is no single label to order a zone by.
    let err = list(&e, "zone", "sort=record").await.unwrap_err();
    assert!(err.to_string().contains("record"), "{err}");
}

#[tokio::test]
async fn an_unknown_sort_key_is_refused() {
    let e = engine_with(Label::Declared).await;
    assert!(list(&e, "record", "sort=nope").await.is_err());
}

// ---- page stability ----

#[tokio::test]
async fn paging_a_tied_sort_column_shows_every_row_exactly_once() {
    // Six of seven records share ttl = 3600. Without the primary key appended as a final sort key the
    // database may order the tie differently for each page's query, so a row can appear on both pages
    // while another appears on neither — the failure clickable sort headers would surface.
    let e = engine_with(Label::Declared).await;
    let mut seen = Vec::new();
    for page in 1..=4 {
        let p = list(&e, "record", &format!("sort=ttl&per_page=2&page={page}")).await.expect("lists");
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
    let e = engine_with(Label::Declared).await;
    let page = list(&e, "record", "filter[zone]=1").await.expect("lists");

    let mut got = names(&page);
    got.sort();
    // Zone 11 exists precisely to catch a substring match: `LIKE '%1%'` would drag ns2 in here.
    assert_eq!(got, vec!["ftp", "www"], "an exact FK match, not a substring one");
    assert_eq!(page.total, 2);
}

#[tokio::test]
async fn a_filter_may_name_a_plain_column_too() {
    let e = engine_with(Label::Declared).await;
    assert_eq!(names(&list(&e, "record", "filter[ttl]=300").await.expect("lists")), vec!["vpn"]);
}

#[tokio::test]
async fn an_empty_filter_value_finds_the_rows_that_have_none() {
    let e = engine_with(Label::Declared).await;
    let page = list(&e, "record", "filter[zone]=").await.expect("lists");
    assert_eq!(names(&page), vec!["orphan"], "an empty value means IS NULL");
}

#[tokio::test]
async fn an_unknown_filter_name_is_refused() {
    let e = engine_with(Label::Declared).await;
    assert!(list(&e, "record", "filter[nope]=1").await.is_err());
}

#[tokio::test]
async fn a_substring_search_on_a_non_text_column_is_refused() {
    // This used to be `ttl LIKE '%300%'`: wrong on SQLite (3000 would match) and a type error on
    // PostgreSQL. Neither is an answer, so it is refused, naming the column. Reached here through
    // `ListQuery` directly, since the UI's toolbar only ever offers the all-text-columns search.
    let e = engine_with(Label::Declared).await;
    let mut q = ListQuery::default();
    q.search.push((Some("ttl".into()), "300".into()));
    let err = e.list("record", &q, false).await.unwrap_err();
    assert!(err.to_string().contains("ttl"), "{err}");

    // A text column is unaffected — the control.
    let mut q = ListQuery::default();
    q.search.push((Some("name".into()), "ns".into()));
    let mut got = names(&e.list("record", &q, false).await.expect("lists"));
    got.sort();
    assert_eq!(got, vec!["ns1", "ns2"]);
}

#[tokio::test]
async fn several_conditions_in_one_query_all_apply() {
    // A `HashMap` of parameters kept only the last of these; both must survive and combine.
    let e = engine_with(Label::Declared).await;
    let page = list(&e, "record", "filter[zone]=2&filter[ttl]=300").await.expect("lists");
    assert_eq!(names(&page), vec!["vpn"]);

    let mut q = ListQuery::default();
    q.search.push((Some("name".into()), "n".into()));
    q.search.push((Some("name".into()), "s".into()));
    let mut got = names(&e.list("record", &q, false).await.expect("lists"));
    got.sort();
    assert_eq!(got, vec!["ns1", "ns2"], "both substring conditions apply, not just the last");
}

#[tokio::test]
async fn a_filtered_bulk_delete_deletes_only_the_matching_rows_and_needs_no_all_flag() {
    let e = engine_with(Label::Declared).await;
    let filtered = ViewState::from_query("filter[zone]=1").to_list_query(25);
    let gone = e.delete_where("record", &filtered).await.expect("a filter is a filter for the guard");
    assert_eq!(gone.len(), 2);
    // The rows come back finished, which is the whole point: after a set-based delete this is the
    // only way anything can learn *what* went — a parent to re-render, an index entry to evict.
    assert!(gone.iter().all(|r| !r["zone"].is_null()), "relations resolved: {gone:?}");
    assert_eq!(list(&e, "record", "").await.expect("lists").total, 5, "other zones untouched");

    // The guard still holds for an unfiltered delete — the UI's "Delete all matching" is what sets
    // the flag, and it says so on the button.
    assert!(e.delete_where("record", &ListQuery::default()).await.is_err());
    let all = ListQuery { all: true, ..Default::default() };
    assert_eq!(e.delete_where("record", &all).await.expect("explicit").len(), 5);
}

#[tokio::test]
async fn a_filter_and_a_sort_compose() {
    let e = engine_with(Label::Declared).await;
    let page = list(&e, "record", "filter[ttl]=3600&sort=name:desc").await.expect("lists");
    assert_eq!(names(&page), vec!["www", "orphan", "ns2", "ns1", "mail", "ftp"]);
}
