//! Option labels over a real database: an enum's options shown by their labels
//! (`MetaField::options_from_display`, `option_labels`) everywhere the UI shows a value — cells,
//! the View dialog, the form's select and radios, filter menus and chips, a pinned set's choices —
//! while every place the value *goes* keeps the stored one: the database, the URL, the posted form,
//! the CSV and the write check. Each label has a control (the same column without labels).
//!
//! The fixture is CLIMB's work order: `state` is `new`, `in_progress` or `done`, and `in_progress`
//! should read "In-Progress".

use crate::authz::Open;
use crate::crud::engine::Engine;
use crate::crud::seaorm::{Crud, MetaModel};
use crate::crud::ui::{Form, Outcome, Table, ViewState};
use http::HeaderMap;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
use std::net::{IpAddr, Ipv4Addr};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

mod workorder {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Copy, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, DeriveDisplay, Serialize, Deserialize,
    )]
    #[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "state")]
    #[serde(rename_all = "snake_case")]
    pub enum State {
        #[sea_orm(string_value = "new")]
        New,
        #[sea_orm(string_value = "in_progress", display_value = "In-Progress")]
        InProgress,
        #[sea_orm(string_value = "done")]
        Done,
    }

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "workorder")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub title: String,
        pub state: Option<State>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `labelled`: the options shown by the enum's `Display`; else as stored (the control).
async fn fixture(labelled: bool) -> (Engine, DatabaseConnection) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    for stmt in [
        "CREATE TABLE workorder (id INTEGER PRIMARY KEY, title TEXT NOT NULL, state TEXT)",
        "INSERT INTO workorder (id, title, state) VALUES \
           (1, 'Engine check', 'in_progress'), (2, 'Tyres', 'new')",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
    let mut crud = Crud::new(db.clone());
    let mut m = MetaModel::new(workorder::Entity);
    if labelled {
        m.field("state").options_from_display::<workorder::State>();
    }
    crud.register(m, Open);
    (crud.into_engine(), db)
}

fn h() -> HeaderMap {
    HeaderMap::new()
}

async fn render(table: &Table<'_>, query: &str) -> String {
    table.render_for(&h(), &ViewState::from_query(query)).await.expect("renders")
}

#[test]
fn options_from_display_takes_the_values_and_the_display() {
    let mut m = MetaModel::new(workorder::Entity);
    m.field("state").options_from_display::<workorder::State>();
    let f = m.field("state");
    assert_eq!(f.options, ["new", "in_progress", "done"]);
    assert_eq!(f.option_labels[1], ("in_progress".to_string(), "In-Progress".to_string()));
    assert_eq!(f.option_labels[0], ("new".to_string(), "New".to_string()), "no display_value: the name");
}

#[tokio::test]
async fn a_label_is_shown_wherever_the_value_is() {
    let (e, _db) = fixture(true).await;
    let table = Table::new(&e, "workorder").filter("state");

    let list = render(&table, "").await;
    assert!(list.contains("<td>In-Progress"), "the cell: {list}");
    assert!(list.contains(r#"<option value="in_progress">In-Progress</option>"#), "the filter menu: {list}");

    let filtered = render(&table, "filter[state]=in_progress").await;
    assert!(
        filtered.contains("In-Progress</span>") || filtered.contains(">In-Progress<"),
        "the chip: {filtered}"
    );
    assert!(
        filtered.contains("<td>Engine check") && !filtered.contains("<td>Tyres"),
        "and it filters: {filtered}"
    );

    let show = render(&table, "show=1").await;
    assert!(show.contains("In-Progress"), "the View dialog: {show}");

    let form = Form::new(&e, "workorder").edit("1").render_for(&h(), &ViewState::default()).await.unwrap();
    assert!(form.contains(r#"<option value="in_progress" selected>In-Progress</option>"#), "the form: {form}");

    let pinned = render(&Table::new(&e, "workorder").fixed_in("state", ["new", "in_progress"]), "new=1").await;
    assert!(pinned.contains("New, In-Progress"), "a pinned set's chip: {pinned}");
    assert!(pinned.contains(r#"<option value="in_progress">In-Progress</option>"#), "its choices: {pinned}");
}

#[tokio::test]
async fn without_labels_the_stored_value_shows_as_before() {
    let (e, _db) = fixture(false).await;
    let list = render(&Table::new(&e, "workorder").filter("state"), "").await;
    assert!(list.contains("<td>in_progress") && !list.contains("In-Progress"), "{list}");
    assert!(list.contains(r#"<option value="in_progress">in_progress</option>"#), "{list}");
}

#[tokio::test]
async fn a_radio_shows_labels_too() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.execute_unprepared("CREATE TABLE workorder (id INTEGER PRIMARY KEY, title TEXT NOT NULL, state TEXT)")
        .await
        .unwrap();
    let mut crud = Crud::new(db.clone());
    let mut m = MetaModel::new(workorder::Entity);
    m.field("state").options_from_display::<workorder::State>().radio();
    crud.register(m, Open);
    let e = crud.into_engine();
    let form = Form::new(&e, "workorder").render_for(&h(), &ViewState::default()).await.unwrap();
    assert!(form.contains(r#"value="in_progress""#) && form.contains(">In-Progress</label>"), "{form}");
}

#[tokio::test]
async fn the_value_not_the_label_is_what_is_stored_posted_and_exported() {
    let (e, db) = fixture(true).await;
    // A write posts the value; a label is not one.
    let form = Form::new(&e, "workorder");
    let ok = form.submit(&h(), IP, b"_op=create&title=Wheels&state=in_progress", &ViewState::default()).await;
    assert!(matches!(ok, Ok(Outcome::Done(_))), "{ok:?}");
    let row = db
        .query_one_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT state FROM workorder WHERE id = 3",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<String>("", "state").unwrap(), "in_progress");
    let refused =
        form.submit(&h(), IP, b"_op=create&title=Brakes&state=In-Progress", &ViewState::default()).await;
    let Ok(Outcome::Invalid(state)) = refused else { panic!("a label is not a value: {refused:?}") };
    let html = form.render_for(&h(), &state).await.unwrap();
    assert!(html.contains("must be one of: new, in_progress, done"), "the check names values: {html}");

    // The filter's URL carries the value.
    let list = render(&Table::new(&e, "workorder").filter("state"), "filter[state]=in_progress").await;
    assert!(list.contains("filter[state]") && list.contains("in_progress"), "{list}");

    #[cfg(feature = "csv")]
    {
        let csv = Table::new(&e, "workorder").csv(&h(), &ViewState::default()).await.unwrap();
        assert!(csv.contains(",in_progress") && !csv.contains("In-Progress"), "{csv}");
    }
}

#[tokio::test]
async fn a_label_is_escaped_and_an_unlisted_option_shows_as_stored() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    for stmt in [
        "CREATE TABLE workorder (id INTEGER PRIMARY KEY, title TEXT NOT NULL, state TEXT)",
        "INSERT INTO workorder (id, title, state) VALUES (1, 'a', 'new'), (2, 'b', 'done')",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
    let mut crud = Crud::new(db.clone());
    let mut m = MetaModel::new(workorder::Entity);
    m.field("state").options_from::<workorder::State>().option_labels([("new", "<b>New</b>")]);
    crud.register(m, Open);
    let e = crud.into_engine();
    let list = render(&Table::new(&e, "workorder"), "").await;
    assert!(!list.contains("<b>New") && list.contains("&#60;b&#62;New"), "escaped: {list}");
    assert!(list.contains("<td>done"), "no label: as stored: {list}");
}
