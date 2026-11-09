//! `Table::range_filter` over a real database: a `.datetime()` column ranged by dates in the
//! viewer's zone with the "to" day inclusive, a number column with open ends, the bounds riding in
//! the URL, and the range holding for the writes that act on the view ("delete all matching").
//! Each narrowing has a control — the same view without the range, or in another zone — so a
//! filter that did nothing can't pass.
//!
//! The fixture is `event`, with a `.datetime()` timestamp `at` and an integer `size`. Its rows sit
//! either side of the November boundaries in **Europe/Prague** (UTC+1 then), so the zone the dates
//! are read in decides which of them November holds.

use crate::authz::Open;
use crate::crud::engine::{Engine, Error, ListQuery};
use crate::crud::seaorm::{Crud, MetaModel};
use crate::crud::ui::{Outcome, Table, ViewState};
use http::HeaderMap;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
use std::net::{IpAddr, Ipv4Addr};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

mod event {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "event")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: String,
        pub at: Option<i64>,
        pub size: i32,
        pub urgent: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// In Prague: `alpha` is 1 Nov 00:30, `bravo` mid-month, `charlie` 30 Nov 23:30 (the last hour of
/// the "to" day), `delta` 1 Dec 00:30. In UTC each of those is an hour earlier, so `alpha` falls in
/// October and `delta` in November. `echo` has no time at all.
async fn fixture() -> (Engine, DatabaseConnection) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    for stmt in [
        "CREATE TABLE event (id INTEGER PRIMARY KEY, name TEXT NOT NULL, at BIGINT, \
           size INTEGER NOT NULL, urgent BOOLEAN NOT NULL)",
        "INSERT INTO event (id, name, at, size, urgent) VALUES \
           (1, 'alpha',   1793489400, 10, 0), \
           (2, 'bravo',   1794744000, 20, 1), \
           (3, 'charlie', 1796077800, 30, 0), \
           (4, 'delta',   1796081400, 40, 1), \
           (5, 'echo',    NULL,       50, 0)",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
    let mut crud = Crud::new(db.clone());
    let mut m = MetaModel::new(event::Entity);
    m.field("at").datetime();
    crud.register(m, Open);
    (crud.into_engine(), db)
}

fn ranged(engine: &Engine) -> Table<'_> {
    Table::new(engine, "event").range_filter("at").range_filter("size")
}

fn zone(name: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(http::header::COOKIE, format!("rl_tz={name}").parse().unwrap());
    h
}

/// The event names a rendered table lists, in the fixture's order.
fn listed(html: &str) -> Vec<&'static str> {
    ["alpha", "bravo", "charlie", "delta", "echo"]
        .into_iter()
        .filter(|name| cell(html, name))
        .collect()
}

async fn render(table: &Table<'_>, headers: &HeaderMap, query: &str) -> String {
    table.render_for(headers, &ViewState::from_query(query)).await.expect("renders")
}

const NOVEMBER: &str = "filter[at][from]=2026-11-01&filter[at][to]=2026-11-30";

#[tokio::test]
async fn a_datetime_range_is_whole_days_in_the_viewers_zone() {
    let (e, _db) = fixture().await;
    // Control: no range, every row.
    let html = render(&ranged(&e), &zone("Europe/Prague"), "").await;
    assert_eq!(listed(&html), ["alpha", "bravo", "charlie", "delta", "echo"], "{html}");

    // November in Prague: from its first second (alpha, 00:30 on the 1st) to its last (charlie,
    // 23:30 on the 30th — the "to" day is inclusive), and not delta, 00:30 on 1 December.
    let html = render(&ranged(&e), &zone("Europe/Prague"), NOVEMBER).await;
    assert_eq!(listed(&html), ["alpha", "bravo", "charlie"], "{html}");

    // The same dates read in UTC are a different hour of the same days: alpha is October there,
    // delta November.
    let html = render(&ranged(&e), &HeaderMap::new(), NOVEMBER).await;
    assert_eq!(listed(&html), ["bravo", "charlie", "delta"], "{html}");
}

#[tokio::test]
async fn the_range_controls_show_what_is_in_force_and_a_chip_clears_it() {
    let (e, _db) = fixture().await;
    let html = render(&ranged(&e), &zone("Europe/Prague"), NOVEMBER).await;
    assert!(html.contains(r#"type="date" class="form-control form-control-sm" name="filter[at][from]""#), "{html}");
    assert!(html.contains(r#"value="2026-11-01""#) && html.contains(r#"value="2026-11-30""#), "{html}");
    assert!(html.contains(r#"name="filter[size][from]""#) && html.contains(r#"step="1""#), "{html}");
    // The chip says it, and its ✕ is this view without the range.
    assert!(html.contains("2026-11-01 – 2026-11-30"), "{html}");
    assert!(html.contains(r#"href="?""#), "the clear link drops both bounds: {html}");
}

#[tokio::test]
async fn a_number_range_may_be_open_at_either_end() {
    let (e, _db) = fixture().await;
    let both = render(&ranged(&e), &HeaderMap::new(), "filter[size][from]=20&filter[size][to]=40").await;
    assert_eq!(listed(&both), ["bravo", "charlie", "delta"], "bounds are inclusive: {both}");
    let from = render(&ranged(&e), &HeaderMap::new(), "filter[size][from]=30").await;
    assert_eq!(listed(&from), ["charlie", "delta", "echo"], "{from}");
    assert!(from.contains("from 30"), "the chip names the one bound: {from}");
    let to = render(&ranged(&e), &HeaderMap::new(), "filter[size][to]=20&filter[size][from]=").await;
    assert_eq!(listed(&to), ["alpha", "bravo"], "an empty input is an open end: {to}");
    assert!(to.contains("to 20"), "{to}");
    // Two ranges compose.
    let html = render(&ranged(&e), &zone("Europe/Prague"), &format!("{NOVEMBER}&filter[size][from]=20")).await;
    assert_eq!(listed(&html), ["bravo", "charlie"], "{html}");
}

#[tokio::test]
async fn a_bound_the_column_cannot_read_applies_nothing_and_claims_nothing() {
    let (e, _db) = fixture().await;
    let html = render(&ranged(&e), &HeaderMap::new(), "filter[size][from]=lots&filter[at][to]=someday").await;
    assert_eq!(listed(&html).len(), 5, "no rows dropped by a bound nobody can read: {html}");
    assert!(!html.contains("from lots") && !html.contains("to someday"), "and no chip for it: {html}");
}

#[tokio::test]
async fn a_range_applies_only_where_the_table_declares_it() {
    let (e, _db) = fixture().await;
    let plain = Table::new(&e, "event");
    let html = render(&plain, &HeaderMap::new(), "filter[size][from]=30").await;
    assert_eq!(listed(&html).len(), 5, "an undeclared range in the URL is ignored: {html}");
    assert!(!html.contains("filter[size][from]"), "and offers no control: {html}");
    // Control: declared, the same URL narrows.
    let html = render(&Table::new(&e, "event").range_filter("size"), &HeaderMap::new(), "filter[size][from]=30").await;
    assert_eq!(listed(&html), ["charlie", "delta", "echo"], "{html}");
}

#[tokio::test]
async fn a_column_with_no_ordering_to_give_is_refused_by_name() {
    let (e, _db) = fixture().await;
    for (column, why) in [("urgent", "Bool"), ("nope", "no such column")] {
        let err = Table::new(&e, "event")
            .range_filter(column)
            .render_for(&HeaderMap::new(), &ViewState::default())
            .await
            .expect_err("refused");
        let msg = err.to_string();
        assert!(msg.contains(&format!("'{column}'")) && msg.contains(why), "{msg}");
    }
}

#[tokio::test]
async fn delete_all_matching_deletes_only_the_range() {
    let (e, db) = fixture().await;
    let state = ViewState::from_query("filter[size][from]=20&filter[size][to]=30");
    let outcome = ranged(&e).submit(&HeaderMap::new(), IP, b"_op=delete_all", &state).await;
    assert!(matches!(outcome, Ok(Outcome::Done(_))), "{outcome:?}");
    let row = db
        .query_one_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT group_concat(name) AS names FROM (SELECT name FROM event ORDER BY id)",
        ))
        .await
        .unwrap()
        .unwrap();
    let left: String = row.try_get("", "names").unwrap();
    assert_eq!(left, "alpha,delta,echo", "bravo and charlie were the view; the rest stays");
}

#[cfg(feature = "csv")]
#[tokio::test]
async fn the_export_is_the_ranged_view() {
    let (e, _db) = fixture().await;
    let csv = ranged(&e)
        .csv(&zone("Europe/Prague"), &ViewState::from_query(NOVEMBER))
        .await
        .unwrap();
    let names: Vec<&str> = csv.lines().skip(1).filter_map(|l| l.split(',').nth(1)).collect();
    assert_eq!(names, ["alpha", "bravo", "charlie"], "{csv}");
}

#[tokio::test]
async fn the_engine_reads_ranges_and_sets_and_an_empty_set_matches_nothing() {
    let (e, _db) = fixture().await;
    let names = |q: ListQuery| {
        let e = &e;
        async move {
            let page = e.list("event", &q, true).await.unwrap();
            page.data.iter().map(|it| it.id.as_i64().unwrap()).collect::<Vec<_>>()
        }
    };
    let range = vec![("size".into(), Some("20".into()), None), ("size".into(), None, Some("40".into()))];
    assert_eq!(names(ListQuery { range, ..Default::default() }).await, [2, 3, 4]);
    let one_of = vec![("size".into(), vec!["10".into(), "50".into()])];
    assert_eq!(names(ListQuery { one_of, ..Default::default() }).await, [1, 5]);
    let none = || ListQuery { one_of: vec![("size".into(), Vec::new())], ..Default::default() };
    let q = none();
    assert_eq!(names(q).await, Vec::<i64>::new(), "a set that allows nothing is not a filter left out");

    // A bulk delete through an empty set deletes nothing — it is a filter, so it needs no `all`.
    assert_eq!(e.delete_where("event", &none()).await.unwrap().len(), 0);
    assert!(matches!(e.delete_where("event", &ListQuery::default()).await, Err(Error::BadRequest(_))));
}

/// Whether a cell of the table holds exactly `text` (a cell is `<td>text` and then whitespace or a
/// tag, so `ns` doesn't match `ns2`).
fn cell(html: &str, text: &str) -> bool {
    let open = format!("<td>{text}");
    html.match_indices(&open)
        .any(|(i, _)| !html[i + open.len()..].starts_with(|c: char| c.is_alphanumeric()))
}
