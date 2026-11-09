//! A pinned filter (`Table::fixed_filter`) holds for the writes, over a real database: the form
//! doesn't render the pinned column, every create and update writes the pinned value whatever the
//! body says, and a row outside the pin is not found through the table — to open, update, delete or
//! import over. Each refusal has a positive control (the same write to a row inside the pin, or the
//! same body through an unpinned table), so the negatives can't pass because nothing works.
//!
//! The fixture is a child table seen from its parent's page: `record` belongs to `zone`, and the
//! table is `record` pinned to zone 1.

use crate::authz::Open;
use crate::crud::engine::{Engine, Error};
use crate::crud::seaorm::{Crud, MetaModel};
use crate::crud::ui::{Outcome, Table, ViewState};
use http::HeaderMap;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
use std::net::{IpAddr, Ipv4Addr};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

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
        pub zone_id: i32,
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

/// Zone 1 has records 1 and 2; zone 2 has record 3 — the row a pinned table must not reach.
async fn fixture() -> (Engine, DatabaseConnection) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    for stmt in [
        "CREATE TABLE zone (id INTEGER PRIMARY KEY, origin TEXT NOT NULL, kind TEXT NOT NULL)",
        "CREATE TABLE record (id INTEGER PRIMARY KEY, name TEXT NOT NULL, zone_id INTEGER NOT NULL)",
        "INSERT INTO zone (id, origin, kind) VALUES (1, 'one.example.', 'primary'), \
           (2, 'two.example.', 'secondary')",
        "INSERT INTO record (id, name, zone_id) VALUES (1, 'www', 1), (2, 'mail', 1), (3, 'ns', 2)",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
    let mut crud = Crud::new(db.clone());
    crud.register(MetaModel::new(zone::Entity), Open);
    crud.register(MetaModel::new(record::Entity), Open);
    (crud.into_engine(), db)
}

fn pinned(engine: &Engine) -> Table<'_> {
    Table::new(engine, "record").fixed_filter("zone", "1")
}

fn list() -> ViewState {
    ViewState::default()
}

async fn submit(table: &Table<'_>, body: &str) -> crate::crud::engine::Result<Outcome> {
    table
        .submit(&HeaderMap::new(), IP, body.as_bytes(), &list())
        .await
}

/// `(name, zone_id)` of a record, or `None` when it is gone.
async fn record(db: &DatabaseConnection, id: i32) -> Option<(String, i64)> {
    let row = db
        .query_one_raw(Statement::from_string(
            db.get_database_backend(),
            format!("SELECT name, zone_id FROM record WHERE id = {id}"),
        ))
        .await
        .unwrap()?;
    Some((
        row.try_get("", "name").unwrap(),
        row.try_get("", "zone_id").unwrap(),
    ))
}

async fn count(db: &DatabaseConnection) -> i64 {
    let row = db
        .query_one_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT COUNT(*) AS n FROM record",
        ))
        .await
        .unwrap()
        .unwrap();
    row.try_get("", "n").unwrap()
}

fn done(outcome: crate::crud::engine::Result<Outcome>) {
    match outcome {
        Ok(Outcome::Done(_)) => {}
        Ok(Outcome::Invalid(state)) => panic!("refused: {:?}", state.row_errors()),
        Err(e) => panic!("failed: {e}"),
    }
}

#[tokio::test]
async fn the_form_leaves_the_pinned_column_out_and_a_create_is_written_with_it() {
    let (e, db) = fixture().await;
    let html = pinned(&e)
        .render_for(&HeaderMap::new(), &ViewState::from_query("new=1"))
        .await
        .unwrap();
    assert!(html.contains(r#"name="name""#), "the form renders: {html}");
    assert!(
        !html.contains(r#"name="zone""#),
        "but not the pinned column: {html}"
    );
    // Positive control: the same table unpinned offers it.
    let html = Table::new(&e, "record")
        .render_for(&HeaderMap::new(), &ViewState::from_query("new=1"))
        .await
        .unwrap();
    assert!(html.contains(r#"name="zone""#), "{html}");

    // The pinned value arrives without being posted — and a crafted one doesn't win.
    done(submit(&pinned(&e), "_op=create&name=ftp").await);
    done(submit(&pinned(&e), "_op=create&name=vpn&zone=2").await);
    assert_eq!(record(&db, 4).await, Some(("ftp".into(), 1)));
    assert_eq!(record(&db, 5).await, Some(("vpn".into(), 1)));
    // Positive control: unpinned, the posted zone is what is written.
    done(submit(&Table::new(&e, "record"), "_op=create&name=dns&zone=2").await);
    assert_eq!(record(&db, 6).await, Some(("dns".into(), 2)));
}

#[tokio::test]
async fn a_required_pinned_column_does_not_make_the_create_form_unsatisfiable() {
    let (e, db) = fixture().await;
    let table = Table::new(&e, "zone").fixed_filter("kind", "secondary");
    let html = table
        .render_for(&HeaderMap::new(), &ViewState::from_query("new=1"))
        .await
        .unwrap();
    assert!(!html.contains(r#"name="kind""#), "{html}");
    done(submit(&table, "_op=create&origin=three.example.").await);
    let row = db
        .query_one_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT kind FROM zone WHERE id = 3",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<String>("", "kind").unwrap(), "secondary");
}

#[tokio::test]
async fn an_update_cannot_reach_a_row_outside_the_pin_or_move_one_out_of_it() {
    let (e, db) = fixture().await;
    let refused = submit(&pinned(&e), "_op=update&_id=3&name=hijacked").await;
    assert!(matches!(refused, Err(Error::NotFound)), "{refused:?}");
    assert_eq!(record(&db, 3).await, Some(("ns".into(), 2)), "untouched");

    // Positive control: a row inside updates — and stays inside, whatever zone was posted.
    done(submit(&pinned(&e), "_op=update&_id=1&name=web&zone=2").await);
    assert_eq!(record(&db, 1).await, Some(("web".into(), 1)));
}

#[tokio::test]
async fn a_one_row_delete_cannot_reach_a_row_outside_the_pin() {
    let (e, db) = fixture().await;
    let refused = submit(&pinned(&e), "_del=3").await;
    assert!(matches!(refused, Err(Error::NotFound)), "{refused:?}");
    assert!(record(&db, 3).await.is_some(), "still there");

    done(submit(&pinned(&e), "_del=2").await);
    assert!(record(&db, 2).await.is_none(), "a row inside is deleted");
}

#[tokio::test]
async fn a_bulk_delete_through_the_pin_deletes_only_rows_inside_it() {
    let (e, db) = fixture().await;
    done(submit(&pinned(&e), "_op=delete_selected&ids=2&ids=3").await);
    assert!(record(&db, 2).await.is_none());
    assert!(record(&db, 3).await.is_some(), "outside the pin");
}

#[tokio::test]
async fn a_row_outside_the_pin_does_not_open_in_a_dialog() {
    let (e, _db) = fixture().await;
    for query in ["edit=3", "show=3"] {
        let refused = pinned(&e)
            .render_for(&HeaderMap::new(), &ViewState::from_query(query))
            .await;
        assert!(
            matches!(refused, Err(Error::NotFound)),
            "{query}: {refused:?}"
        );
    }
    let html = pinned(&e)
        .render_for(&HeaderMap::new(), &ViewState::from_query("edit=1"))
        .await
        .unwrap();
    assert!(
        html.contains(r#"value="www""#),
        "a row inside opens: {html}"
    );
    let html = pinned(&e)
        .render_for(&HeaderMap::new(), &ViewState::from_query("show=1"))
        .await
        .unwrap();
    assert!(html.contains("www"), "{html}");
}

#[cfg(feature = "csv")]
#[tokio::test]
async fn an_import_is_written_with_the_pin_and_cannot_update_a_row_outside_it() {
    let (e, db) = fixture().await;
    let import = |csv: &str| format!("_op=import&csv={}", crate::urlform::encode(csv));

    // A row naming a key outside the pin rejects the file: nothing applies.
    let Outcome::Invalid(state) =
        submit(&pinned(&e), &import("id,name,zone\n,ftp,1\n3,hijacked,2\n"))
            .await
            .unwrap()
    else {
        panic!("refused")
    };
    assert!(
        state
            .row_errors()
            .iter()
            .any(|m| m.contains("line 3") && m.contains("no row 3")),
        "{:?}",
        state.row_errors()
    );
    assert_eq!(count(&db).await, 3, "nothing imported");
    assert_eq!(record(&db, 3).await, Some(("ns".into(), 2)));

    // Positive control: rows inside update, new rows are created — all in the pinned zone.
    done(submit(&pinned(&e), &import("id,name,zone\n1,web,2\n,ftp,2\n")).await);
    assert_eq!(record(&db, 1).await, Some(("web".into(), 1)));
    assert_eq!(record(&db, 4).await, Some(("ftp".into(), 1)));
}

// ---------- `fixed_in`: a pin to a set ----------
//
// The same fixture plus zone 3 holding record 4, and the table pinned to zones 1 and 3: records
// 1, 2 and 4 are inside, record 3 (zone 2) is the row it must not reach.

async fn with_zone_three(db: &DatabaseConnection) {
    for stmt in [
        "INSERT INTO zone (id, origin, kind) VALUES (3, 'three.example.', 'primary')",
        "INSERT INTO record (id, name, zone_id) VALUES (4, 'dns', 3)",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
}

fn in_set(engine: &Engine) -> Table<'_> {
    Table::new(engine, "record").fixed_in("zone", ["1", "3"])
}

/// The record names a rendered table lists.
fn listed(html: &str) -> Vec<&'static str> {
    ["www", "mail", "ns", "dns"].into_iter().filter(|n| cell(html, n)).collect()
}

/// The field messages a refused write came back with.
fn refused(outcome: crate::crud::engine::Result<Outcome>) -> String {
    match outcome {
        Ok(Outcome::Invalid(state)) => {
            let html_of = |name: &str| state.field_error(name).unwrap_or_default().to_string();
            format!("{}{}", html_of("zone"), html_of("kind"))
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_set_pin_lists_only_rows_inside_it_and_says_so() {
    let (e, db) = fixture().await;
    with_zone_three(&db).await;
    let html = in_set(&e).render_for(&HeaderMap::new(), &list()).await.unwrap();
    assert_eq!(listed(&html), ["www", "mail", "dns"], "{html}");
    assert!(html.contains("#1, #3"), "a chip names the set, by the target's labels: {html}");
    // Control: unpinned, the outside row is there.
    let html = Table::new(&e, "record").render_for(&HeaderMap::new(), &list()).await.unwrap();
    assert_eq!(listed(&html), ["www", "mail", "ns", "dns"]);
    // A URL filter can narrow inside the set, never widen past it.
    let html = in_set(&e).render_for(&HeaderMap::new(), &ViewState::from_query("filter[zone]=2")).await.unwrap();
    assert!(listed(&html).is_empty(), "{html}");
}

#[tokio::test]
async fn a_row_outside_the_set_does_not_open_and_cannot_be_written() {
    let (e, db) = fixture().await;
    with_zone_three(&db).await;
    for query in ["edit=3", "show=3"] {
        let r = in_set(&e).render_for(&HeaderMap::new(), &ViewState::from_query(query)).await;
        assert!(matches!(r, Err(Error::NotFound)), "{query}: {r:?}");
    }
    let r = submit(&in_set(&e), "_op=update&_id=3&name=hijacked&zone=1").await;
    assert!(matches!(r, Err(Error::NotFound)), "{r:?}");
    let r = submit(&in_set(&e), "_del=3").await;
    assert!(matches!(r, Err(Error::NotFound)), "{r:?}");
    assert_eq!(record(&db, 3).await, Some(("ns".into(), 2)), "untouched");

    // Controls: rows inside open, update and delete.
    let html = in_set(&e).render_for(&HeaderMap::new(), &ViewState::from_query("edit=4")).await.unwrap();
    assert!(html.contains(r#"value="dns""#), "{html}");
    done(submit(&in_set(&e), "_op=update&_id=4&name=dns2&zone=3").await);
    assert_eq!(record(&db, 4).await, Some(("dns2".into(), 3)));
    done(submit(&in_set(&e), "_del=2").await);
    assert!(record(&db, 2).await.is_none());

    // A bulk delete acts on the pinned view.
    done(submit(&in_set(&e), "_op=delete_selected&ids=1&ids=3").await);
    assert!(record(&db, 1).await.is_none() && record(&db, 3).await.is_some());
}

#[tokio::test]
async fn the_form_offers_only_the_set() {
    let (e, db) = fixture().await;
    with_zone_three(&db).await;
    let html = in_set(&e).render_for(&HeaderMap::new(), &ViewState::from_query("new=1")).await.unwrap();
    assert!(html.contains(r#"name="zone""#), "unlike a single-value pin, the column is a choice: {html}");
    assert!(html.contains(r#"<option value="1""#) && html.contains(r#"<option value="3""#), "{html}");
    assert!(!html.contains(r#"<option value="2""#), "and only among the set: {html}");
    assert!(!html.contains(r#"<option value="""#), "with no blank, since blank isn't in it: {html}");
}

#[tokio::test]
async fn a_write_must_carry_a_value_in_the_set() {
    let (e, db) = fixture().await;
    with_zone_three(&db).await;
    // A create without the column, or with a value outside the set, is refused beside the field.
    let msg = refused(submit(&in_set(&e), "_op=create&name=ftp").await);
    assert!(msg.contains("must be one of the zone rows this view allows"), "{msg}");
    let msg = refused(submit(&in_set(&e), "_op=create&name=ftp&zone=2").await);
    assert!(!msg.is_empty());
    assert_eq!(count(&db).await, 4, "nothing created");
    // An update can't move a row out of the view either.
    refused(submit(&in_set(&e), "_op=update&_id=1&name=www&zone=2").await);
    assert_eq!(record(&db, 1).await, Some(("www".into(), 1)), "still inside");

    // Controls: a value in the set is written as posted.
    done(submit(&in_set(&e), "_op=create&name=ftp&zone=3").await);
    assert_eq!(record(&db, 5).await, Some(("ftp".into(), 3)));
    done(submit(&in_set(&e), "_op=update&_id=1&name=www&zone=3").await);
    assert_eq!(record(&db, 1).await, Some(("www".into(), 3)));

    // A plain column, same rule, with the set named in the message.
    let zones = Table::new(&e, "zone").fixed_in("kind", ["primary", "tertiary"]);
    let msg = refused(submit(&zones, "_op=create&origin=four.example.&kind=secondary").await);
    assert!(msg.contains("must be one of: primary, tertiary"), "{msg}");
    done(submit(&zones, "_op=create&origin=four.example.&kind=tertiary").await);
}

#[tokio::test]
async fn an_empty_set_shows_no_rows_and_offers_no_create() {
    let (e, _db) = fixture().await;
    let none = Table::new(&e, "record").fixed_in("zone", Vec::<String>::new());
    let html = none.render_for(&HeaderMap::new(), &list()).await.unwrap();
    assert!(listed(&html).is_empty(), "an empty set is no rows, not no restriction: {html}");
    assert!(!html.contains("+ New"), "nothing a new row could hold: {html}");
    let r = submit(&none, "_op=create&name=ftp&zone=1").await;
    assert!(matches!(r, Err(Error::Forbidden)), "{r:?}");
    // Control: the same table with a set offers the button.
    let html = in_set(&e).render_for(&HeaderMap::new(), &list()).await.unwrap();
    assert!(html.contains("+ New"), "{html}");
}

#[tokio::test]
async fn a_set_on_a_column_the_entity_lacks_is_refused_by_name() {
    let (e, _db) = fixture().await;
    let err = Table::new(&e, "record")
        .fixed_in("nope", ["1"])
        .render_for(&HeaderMap::new(), &list())
        .await
        .expect_err("refused");
    assert!(err.to_string().contains("'nope'"), "{err}");
}

#[cfg(feature = "csv")]
#[tokio::test]
async fn an_import_through_a_set_pin_stays_inside_it() {
    let (e, db) = fixture().await;
    with_zone_three(&db).await;
    let import = |csv: &str| format!("_op=import&csv={}", crate::urlform::encode(csv));

    // A new row outside the set, or a key outside the view: the file is refused whole.
    for csv in ["id,name,zone\n,ftp,2\n", "id,name,zone\n3,hijacked,1\n", "id,name,zone\n1,www,2\n"] {
        let Outcome::Invalid(state) = submit(&in_set(&e), &import(csv)).await.unwrap() else {
            panic!("refused: {csv}")
        };
        assert!(!state.row_errors().is_empty(), "{csv}");
    }
    assert_eq!(count(&db).await, 4, "nothing imported");
    assert_eq!(record(&db, 1).await, Some(("www".into(), 1)));

    // Control: inside the set, it applies.
    done(submit(&in_set(&e), &import("id,name,zone\n1,web,3\n,ftp,1\n")).await);
    assert_eq!(record(&db, 1).await, Some(("web".into(), 3)));
    assert_eq!(record(&db, 5).await, Some(("ftp".into(), 1)));
}

/// Whether a cell of the table holds exactly `text` (a cell is `<td>text` and then whitespace or a
/// tag, so `ns` doesn't match `ns2`).
fn cell(html: &str, text: &str) -> bool {
    let open = format!("<td>{text}");
    html.match_indices(&open)
        .any(|(i, _)| !html[i + open.len()..].starts_with(|c: char| c.is_alphanumeric()))
}
