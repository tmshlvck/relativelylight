//! The picker's two ways past choosing, over a real database. **"+ New"** on a relation field
//! (`Crud::picker_create`): the button is offered only
//! when switched on and when the caller may create **and** list the target; the picker's create form
//! is the target's own, refused by the same gates, only ever creates, and checks CSRF; a save lands
//! on a page that reports the new row's id and label; and the form inside the dialog has its own
//! "+", which is how the dialogs nest. **Relation links** (`Crud::picker_view`): a relation's label
//! links to the row when the caller may read it; the row's page shows it with Edit only for who may
//! update it; the edit updates exactly the row the URL names and reports its new label. Each
//! refusal has a control that passes.
//!
//! The fixture is CLIMB's shape: a `workorder` points at an `airline`, which points at its `hq`
//! `address`. Creating a work order for an airline that doesn't exist yet means creating the
//! airline, which means creating its address.

use crate::authz::{Authz, Decision, Open, Operation};
use crate::crud::engine::{Engine, Error};
use crate::crud::seaorm::{Crud, MetaModel};
use crate::crud::ui::{Form, Outcome, Picker, Table, ViewState};
use async_trait::async_trait;
use http::HeaderMap;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
use std::net::{IpAddr, Ipv4Addr};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

mod address {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "address")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub street: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod airline {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "airline")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: String,
        pub code: Option<String>,
        pub hq_id: i32,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::address::Entity",
            from = "Column::HqId",
            to = "super::address::Column::Id"
        )]
        Hq,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

mod workorder {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "workorder")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub title: String,
        pub airline_id: i32,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::airline::Entity",
            from = "Column::AirlineId",
            to = "super::airline::Column::Id"
        )]
        Airline,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

/// The airline table's gate, per test.
#[derive(Clone, Copy)]
enum Gate {
    Open,
    /// Everything but creating: an operator who may pick an airline, not add one.
    NoCreate,
    /// Creating and editing, but no listing: "+" would make a row whose label they may not read.
    WriteOnly,
    /// Listing but not reading one row: no link to open.
    NoRead,
    /// Reading but not updating: the row's page, without Edit.
    NoUpdate,
}

#[async_trait]
impl Authz for Gate {
    async fn authorize(&self, op: Operation, _headers: &HeaderMap) -> Decision {
        match (self, op) {
            (Gate::NoCreate, Operation::Create) => Decision::Denied,
            (Gate::WriteOnly, Operation::List | Operation::Read) => Decision::Denied,
            (Gate::NoRead, Operation::Read) => Decision::Denied,
            (Gate::NoUpdate, Operation::Update) => Decision::Denied,
            _ => Decision::Allow,
        }
    }
}

struct Setup {
    on: bool,
    except: Vec<&'static str>,
    view: bool,
    view_path: Option<&'static str>,
    airline_gate: Gate,
    #[cfg(feature = "csrf")]
    csrf: Option<crate::csrf::Csrf>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            on: true,
            except: Vec::new(),
            view: false,
            view_path: None,
            airline_gate: Gate::Open,
            #[cfg(feature = "csrf")]
            csrf: None,
        }
    }
}

async fn fixture(setup: Setup) -> (Engine, DatabaseConnection) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    for stmt in [
        "CREATE TABLE address (id INTEGER PRIMARY KEY, street TEXT NOT NULL)",
        "CREATE TABLE airline (id INTEGER PRIMARY KEY, name TEXT NOT NULL, code TEXT, \
           hq_id INTEGER NOT NULL REFERENCES address(id))",
        "CREATE TABLE workorder (id INTEGER PRIMARY KEY, title TEXT NOT NULL, \
           airline_id INTEGER NOT NULL REFERENCES airline(id))",
        "INSERT INTO address (id, street) VALUES (1, 'Amsterdamseweg 55')",
        "INSERT INTO airline (id, name, code, hq_id) VALUES (1, 'KLM', 'KL', 1)",
        "INSERT INTO workorder (id, title, airline_id) VALUES (1, 'Engine check', 1)",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
    let mut crud = Crud::new(db.clone());
    crud.picker_path("/pick");
    crud.picker_create(setup.on);
    crud.picker_create_except(setup.except);
    crud.picker_view(setup.view);
    if let Some(path) = setup.view_path {
        crud.view_path("airline", path);
    }
    #[cfg(feature = "csrf")]
    if let Some(csrf) = setup.csrf {
        crud.csrf(csrf);
    }
    crud.register(MetaModel::new(address::Entity), Open);
    let mut airline = MetaModel::new(airline::Entity);
    airline.field("name").validate_str(|s| if s.trim().is_empty() { Err("required".into()) } else { Ok(()) });
    crud.register(airline, setup.airline_gate);
    crud.register(MetaModel::new(workorder::Entity), Open);
    (crud.into_engine(), db)
}

fn h() -> HeaderMap {
    HeaderMap::new()
}

fn q(query: &str) -> ViewState {
    ViewState::from_query(query)
}

/// The work order's create form, whose `airline` is what the "+" is for.
async fn workorder_form(e: &Engine) -> String {
    Form::new(e, "workorder").render_for(&h(), &ViewState::default()).await.expect("renders")
}

const PLUS_AIRLINE: &str = r#"data-rl-src="/pick?pick=workorder.airline&#38;new=1""#;
const PLUS_HQ: &str = r#"data-rl-src="/pick?pick=airline.hq&#38;new=1""#;

async fn airlines(db: &DatabaseConnection) -> Vec<String> {
    let rows = db
        .query_all_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT name FROM airline ORDER BY id",
        ))
        .await
        .unwrap();
    rows.iter().map(|r| r.try_get::<String>("", "name").unwrap()).collect()
}

#[tokio::test]
async fn the_plus_is_offered_only_when_switched_on() {
    let (off, _db) = fixture(Setup { on: false, ..Default::default() }).await;
    let html = workorder_form(&off).await;
    assert!(!html.contains("rl-new"), "off by default: {html}");
    for query in ["pick=workorder.airline&new=1", "pick=workorder.airline&created=1"] {
        let r = Picker::new(&off).render_for(&h(), &q(query)).await;
        assert!(matches!(r, Err(Error::BadRequest(_))), "{query} is not served when off: {r:?}");
    }
    let r = Picker::new(&off)
        .submit(&h(), IP, b"_op=create&name=x&hq=1", &q("pick=workorder.airline&new=1"))
        .await;
    assert!(matches!(r, Err(Error::BadRequest(_))), "nor written: {r:?}");
    // The plain picker is unaffected.
    Picker::new(&off).render_for(&h(), &q("pick=workorder.airline")).await.expect("the list still works");

    let (on, _db) = fixture(Setup::default()).await;
    let html = workorder_form(&on).await;
    assert!(html.contains(PLUS_AIRLINE), "control: on, it is there: {html}");
    let select = html.find(r#"<select class="form-select" id="f-airline""#).expect("a small select");
    let plus = html.find(PLUS_AIRLINE).unwrap();
    assert!(plus > select, "below the select: {html}");
    assert!(
        html.contains(r#"class="btn btn-primary btn-sm mt-1 rl-new" type="button" hidden"#),
        "hidden until the script: {html}"
    );
}

#[tokio::test]
async fn the_plus_follows_the_targets_create_and_list_gates() {
    for (gate, why) in [(Gate::NoCreate, "may not create"), (Gate::WriteOnly, "may not list")] {
        let (e, db) = fixture(Setup { airline_gate: gate, ..Default::default() }).await;
        let html = Form::new(&e, "workorder").render_for(&h(), &ViewState::default()).await.unwrap();
        assert!(!html.contains(PLUS_AIRLINE), "{why}: no +: {html}");

        let state = q("pick=workorder.airline&new=1");
        let r = Picker::new(&e).render_for(&h(), &state).await;
        assert!(matches!(r, Err(Error::Forbidden)), "{why}: the form is refused: {r:?}");
        let r = Picker::new(&e).submit(&h(), IP, b"_op=create&name=Sneaky&hq=1", &state).await;
        assert!(matches!(r, Err(Error::Forbidden)), "{why}: so is the write: {r:?}");
        assert_eq!(airlines(&db).await, ["KLM"], "{why}: nothing written");
    }
}

#[tokio::test]
async fn a_saved_row_is_reported_by_id_and_label_for_the_dialog_to_choose() {
    let (e, db) = fixture(Setup::default()).await;
    let state = q("pick=workorder.airline&new=1");
    let form = Picker::new(&e).render_for(&h(), &state).await.unwrap();
    assert!(
        form.contains(r#"name="name""#) && form.contains(r#"value="create""#),
        "the airline's create form: {form}"
    );
    assert!(form.contains(">Create<"), "{form}");

    let outcome =
        Picker::new(&e).submit(&h(), IP, b"_op=create&name=Lufthansa&code=LH&hq=1", &state).await.unwrap();
    let Outcome::Done(to) = outcome else { panic!("saved: {outcome:?}") };
    assert_eq!(to, "?pick=workorder.airline&created=2", "the id the database gave it");
    assert_eq!(airlines(&db).await, ["KLM", "Lufthansa"]);

    let page = Picker::new(&e).render_for(&h(), &q(&to)).await.unwrap();
    assert!(
        page.contains(r#"class="alert alert-success rl-created" data-id="2" data-label="Lufthansa""#),
        "{page}"
    );
}

#[tokio::test]
async fn a_rejected_save_comes_back_as_the_form_with_its_messages() {
    let (e, db) = fixture(Setup::default()).await;
    let state = q("pick=workorder.airline&new=1");
    let outcome = Picker::new(&e).submit(&h(), IP, b"_op=create&name=&code=XX&hq=1", &state).await.unwrap();
    let Outcome::Invalid(again) = outcome else { panic!("refused: {outcome:?}") };
    let html = Picker::new(&e).render_for(&h(), &again).await.unwrap();
    assert!(
        html.contains("is-invalid") && html.contains(r#"value="XX""#),
        "messages and the typed input: {html}"
    );
    assert!(!html.contains("rl-created"), "{html}");
    assert_eq!(airlines(&db).await, ["KLM"]);
}

#[tokio::test]
async fn the_create_form_only_ever_creates() {
    let (e, db) = fixture(Setup::default()).await;
    let state = q("pick=workorder.airline&new=1");
    for body in ["_op=update&_id=1&name=Hijacked&hq=1", "_op=delete&_id=1"] {
        let r = Picker::new(&e).submit(&h(), IP, body.as_bytes(), &state).await;
        assert!(r.is_err(), "{body}: {r:?}");
    }
    let r = Picker::new(&e).submit(&h(), IP, b"_op=create&name=x&hq=1", &q("pick=workorder.airline")).await;
    assert!(matches!(r, Err(Error::BadRequest(_))), "a write needs the create page's URL: {r:?}");
    assert_eq!(airlines(&db).await, ["KLM"], "KLM untouched");
}

#[tokio::test]
async fn the_form_in_the_dialog_has_its_own_plus_which_is_how_dialogs_nest() {
    let (e, _db) = fixture(Setup::default()).await;
    let airline = Picker::new(&e).render_for(&h(), &q("pick=workorder.airline&new=1")).await.unwrap();
    assert!(airline.contains(PLUS_HQ), "a new airline can get a new address: {airline}");
    let address = Picker::new(&e).render_for(&h(), &q("pick=airline.hq&new=1")).await.unwrap();
    assert!(!address.contains("rl-new"), "an address points nowhere, so the chain ends: {address}");
}

#[tokio::test]
async fn the_create_form_shows_the_fields_the_app_chose_for_that_target() {
    let (e, db) = fixture(Setup::default()).await;
    let picker = Picker::new(&e).create_fields("airline", ["name", "hq"]);
    let html = picker.render_for(&h(), &q("pick=workorder.airline&new=1")).await.unwrap();
    assert!(html.contains(r#"name="name""#) && !html.contains(r#"name="code""#), "{html}");
    let Outcome::Done(_) = picker
        .submit(&h(), IP, b"_op=create&name=Swiss&code=LX&hq=1", &q("pick=workorder.airline&new=1"))
        .await
        .unwrap()
    else {
        panic!("saved")
    };
    // A column the form didn't render is ignored, as on every form.
    let row = db
        .query_one_raw(Statement::from_string(
            db.get_database_backend(),
            "SELECT code FROM airline WHERE id = 2",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<Option<String>>("", "code").unwrap(), None);

    // A field the target doesn't have is a render-time error naming it, as on any form.
    let err = picker
        .create_fields("airline", ["name", "hq", "nope"])
        .render_for(&h(), &q("pick=workorder.airline&new=1"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("nope"), "{err}");
}

#[tokio::test]
async fn the_reported_label_is_escaped() {
    let (e, _db) = fixture(Setup::default()).await;
    let body = b"_op=create&name=%3Cscript%3Ealert(1)%3C%2Fscript%3E&hq=1";
    let Outcome::Done(to) =
        Picker::new(&e).submit(&h(), IP, body, &q("pick=workorder.airline&new=1")).await.unwrap()
    else {
        panic!("saved")
    };
    let page = Picker::new(&e).render_for(&h(), &q(&to)).await.unwrap();
    assert!(!page.contains("<script>"), "{page}");
    assert!(page.contains("&#60;script&#62;"), "{page}");
}

#[tokio::test]
async fn a_pinned_set_offers_no_plus_a_free_relation_does() {
    let (e, _db) = fixture(Setup::default()).await;
    let pinned = Table::new(&e, "workorder").fixed_in("airline", ["1"]);
    let html = pinned.render_for(&h(), &q("new=1")).await.unwrap();
    assert!(!html.contains(PLUS_AIRLINE), "a new airline could never be in the set: {html}");
    let html = Table::new(&e, "workorder").render_for(&h(), &q("new=1")).await.unwrap();
    assert!(html.contains(PLUS_AIRLINE), "control: the table's own dialog offers it: {html}");
}

#[tokio::test]
async fn a_relation_past_the_threshold_puts_its_new_button_in_the_picker() {
    let (e, _db) = fixture(Setup::default()).await;
    let html =
        Form::new(&e, "workorder").picker_threshold(0).render_for(&h(), &ViewState::default()).await.unwrap();
    // The form has no button of its own; the field tells the picker's dialog where "New" goes.
    assert!(!html.contains("rl-new\""), "no + in the form: {html}");
    assert!(html.contains(r#"data-rl-new="/pick?pick=workorder.airline&#38;new=1""#), "{html}");

    let (off, _db) = fixture(Setup { on: false, ..Default::default() }).await;
    let html = Form::new(&off, "workorder")
        .picker_threshold(0)
        .render_for(&h(), &ViewState::default())
        .await
        .unwrap();
    assert!(html.contains("rl-picked") && !html.contains("data-rl-new"), "control: off, none: {html}");
}

#[cfg(feature = "csrf")]
#[tokio::test]
async fn the_create_form_checks_csrf_like_every_write() {
    let csrf = crate::csrf::Csrf::new().secure(false);
    let jar = format!("{}={}", csrf.cookie(), "c".repeat(64));
    let (e, db) = fixture(Setup { csrf: Some(csrf), ..Default::default() }).await;
    let mut headers = HeaderMap::new();
    headers.insert(http::header::COOKIE, jar.parse().unwrap());
    let state = q("pick=workorder.airline&new=1");

    let form = Picker::new(&e).render_for(&headers, &state).await.unwrap();
    assert!(form.contains(&format!(r#"name="_csrf" value="{}""#, "c".repeat(64))), "{form}");
    let r = Picker::new(&e).submit(&headers, IP, b"_op=create&name=Nope&hq=1", &state).await;
    assert!(matches!(r, Err(Error::Csrf)), "{r:?}");
    let body = format!("_op=create&name=Yes&hq=1&_csrf={}", "c".repeat(64));
    let r = Picker::new(&e).submit(&headers, IP, body.as_bytes(), &state).await;
    assert!(matches!(r, Ok(Outcome::Done(_))), "control: with the token: {r:?}");
    assert_eq!(airlines(&db).await, ["KLM", "Yes"]);
}

#[tokio::test]
async fn an_excepted_target_gets_no_plus_whatever_its_gate_allows() {
    let (e, db) = fixture(Setup { except: vec!["airline"], ..Default::default() }).await;
    let html = workorder_form(&e).await;
    assert!(!html.contains(PLUS_AIRLINE), "excepted: {html}");
    let state = q("pick=workorder.airline&new=1");
    let r = Picker::new(&e).render_for(&h(), &state).await;
    assert!(matches!(r, Err(Error::BadRequest(_))), "its create form is not served: {r:?}");
    let r = Picker::new(&e).submit(&h(), IP, b"_op=create&name=Sneaky&hq=1", &state).await;
    assert!(matches!(r, Err(Error::BadRequest(_))), "nor written: {r:?}");
    assert_eq!(airlines(&db).await, ["KLM"]);
    // Control: the airline form's own relation, to an address, still has its "+ New".
    let airline = Form::new(&e, "airline").render_for(&h(), &ViewState::default()).await.unwrap();
    assert!(airline.contains(r#"data-rl-src="/pick?pick=airline.hq&#38;new=1""#), "{airline}");
}

// ---- relation links: viewing (and editing) the linked row ----

fn viewing() -> Setup {
    Setup { view: true, ..Default::default() }
}

const KLM_LINK: &str = concat!(
    r#"<a class="rl-view" href="/pick?pick=workorder.airline&#38;show=1" "#,
    r#"data-rl-view="/pick?pick=workorder.airline&#38;show=1" data-rl-key="airline:1">KLM</a>"#
);

async fn workorders(e: &Engine, query: &str) -> String {
    Table::new(e, "workorder").render_for(&h(), &q(query)).await.expect("renders")
}

#[tokio::test]
async fn a_relation_links_to_its_row_only_when_switched_on() {
    let (off, _db) = fixture(Setup::default()).await;
    let html = workorders(&off, "").await;
    assert!(html.contains("KLM") && !html.contains("rl-view"), "off by default: {html}");
    for query in ["pick=workorder.airline&show=1", "pick=workorder.airline&edit=1"] {
        let r = Picker::new(&off).render_for(&h(), &q(query)).await;
        assert!(matches!(r, Err(Error::BadRequest(_))), "{query} is not served when off: {r:?}");
    }

    let (on, _db) = fixture(viewing()).await;
    assert!(workorders(&on, "").await.contains(KLM_LINK), "control: on, the cell links");
    assert!(workorders(&on, "show=1").await.contains(KLM_LINK), "and so does the View dialog");
    // In the picker's list a click chooses a row; it doesn't open one.
    let pick = Picker::new(&on).render_for(&h(), &q("pick=airline.hq")).await.unwrap();
    assert!(!pick.contains("rl-view"), "{pick}");
}

#[tokio::test]
async fn without_the_script_a_link_goes_to_the_apps_own_page_for_the_target() {
    let (e, _db) = fixture(Setup { view_path: Some("/airlines?show={id}"), ..viewing() }).await;
    let html = workorders(&e, "").await;
    assert!(
        html.contains(r#"href="/airlines?show=1" data-rl-view="/pick?pick=workorder.airline&#38;show=1""#),
        "{html}"
    );
}

#[tokio::test]
async fn a_link_follows_the_targets_read_gate_and_edit_its_update_gate() {
    let (e, db) = fixture(Setup { airline_gate: Gate::NoRead, ..viewing() }).await;
    let html = workorders(&e, "").await;
    assert!(html.contains("KLM") && !html.contains("rl-view"), "may not read: text: {html}");
    let r = Picker::new(&e).render_for(&h(), &q("pick=workorder.airline&show=1")).await;
    assert!(matches!(r, Err(Error::Forbidden)), "{r:?}");

    let (e, _) = fixture(Setup { airline_gate: Gate::NoUpdate, ..viewing() }).await;
    let page = Picker::new(&e).render_for(&h(), &q("pick=workorder.airline&show=1")).await.unwrap();
    assert!(page.contains("KLM") && !page.contains(">Edit<"), "may read, not update: no Edit: {page}");
    let state = q("pick=workorder.airline&edit=1");
    let r = Picker::new(&e).render_for(&h(), &state).await;
    assert!(matches!(r, Err(Error::Forbidden)), "the form is refused: {r:?}");
    let r = Picker::new(&e).submit(&h(), IP, b"_op=update&_id=1&name=Renamed&hq=1", &state).await;
    assert!(matches!(r, Err(Error::Forbidden)), "and the write: {r:?}");
    assert_eq!(airlines(&db).await, ["KLM"]);
}

#[tokio::test]
async fn the_rows_page_has_edit_and_links_of_its_own() {
    let (e, _db) = fixture(viewing()).await;
    let page = Picker::new(&e).render_for(&h(), &q("pick=workorder.airline&show=1")).await.unwrap();
    assert!(!page.contains("<dialog"), "bare: the picker's dialog is the frame: {page}");
    assert!(page.contains(r#"href="?pick=workorder.airline&#38;edit=1">Edit<"#), "{page}");
    assert!(page.contains(r#"data-rl-view="/pick?pick=airline.hq&#38;show=1""#), "its HQ links on: {page}");
    let form = Picker::new(&e).render_for(&h(), &q("pick=workorder.airline&edit=1")).await.unwrap();
    assert!(form.contains(r#"value="KLM""#) && form.contains(r#"name="_id" value="1""#), "{form}");
    assert!(form.contains(r#"href="?pick=workorder.airline&#38;show=1">Cancel<"#), "back to the row: {form}");

    // The dialog is the card: these pages draw none, and put their buttons where the script moves
    // them into the dialog's footer.
    let new = Picker::new(&e).render_for(&h(), &q("pick=workorder.airline&new=1")).await.unwrap();
    for html in [&page, &form, &new] {
        assert!(!html.contains(r#"class="card"#) && html.contains(r#"class="rl-foot"#), "{html}");
    }
    // Control: the table's own View dialog and a standalone form keep theirs.
    let own = Table::new(&e, "airline").render_for(&h(), &q("show=1")).await.unwrap();
    let standalone = Form::new(&e, "airline").render_for(&h(), &ViewState::default()).await.unwrap();
    for html in [&own, &standalone] {
        assert!(html.contains(r#"<div class="card"#) && !html.contains("rl-foot"), "{html}");
    }
}

#[tokio::test]
async fn an_edit_saves_that_row_and_reports_its_new_label() {
    let (e, db) = fixture(viewing()).await;
    let state = q("pick=workorder.airline&edit=1");
    let outcome =
        Picker::new(&e).submit(&h(), IP, b"_op=update&_id=1&name=KLM+Royal&hq=1", &state).await.unwrap();
    let Outcome::Done(to) = outcome else { panic!("saved: {outcome:?}") };
    assert_eq!(to, "?pick=workorder.airline&show=1&saved=1");
    assert_eq!(airlines(&db).await, ["KLM Royal"]);
    let page = Picker::new(&e).render_for(&h(), &q(&to)).await.unwrap();
    assert!(
        page.contains(
            r#"class="alert alert-success rl-saved" data-rl-key="airline:1" data-label="KLM Royal""#
        ),
        "{page}"
    );
    // Control: a plain view reports nothing.
    let page = Picker::new(&e).render_for(&h(), &q("pick=workorder.airline&show=1")).await.unwrap();
    assert!(!page.contains("rl-saved"), "{page}");
}

#[tokio::test]
async fn the_edit_form_updates_only_the_row_its_url_names() {
    let (e, db) = fixture(viewing()).await;
    db.execute_unprepared("INSERT INTO airline (id, name, code, hq_id) VALUES (2, 'Delta', 'DL', 1)")
        .await
        .unwrap();
    let state = q("pick=workorder.airline&edit=1");
    for body in ["_op=update&_id=2&name=Hijacked&hq=1", "_op=create&name=Sneaky&hq=1", "_op=delete&_id=1"] {
        let r = Picker::new(&e).submit(&h(), IP, body.as_bytes(), &state).await;
        assert!(r.is_err(), "{body}: {r:?}");
    }
    assert_eq!(airlines(&db).await, ["KLM", "Delta"], "nothing written");
    // A rejected edit comes back as the form, with its messages.
    let outcome = Picker::new(&e).submit(&h(), IP, b"_op=update&_id=1&name=&hq=1", &state).await.unwrap();
    let Outcome::Invalid(again) = outcome else { panic!("refused: {outcome:?}") };
    let html = Picker::new(&e).render_for(&h(), &again).await.unwrap();
    assert!(html.contains("is-invalid"), "{html}");
}

#[tokio::test]
async fn a_links_label_is_escaped_and_so_is_the_saved_report() {
    let (e, _db) = fixture(viewing()).await;
    let state = q("pick=workorder.airline&edit=1");
    let body = b"_op=update&_id=1&name=%3Cscript%3Ex%3C%2Fscript%3E&hq=1";
    let Outcome::Done(to) = Picker::new(&e).submit(&h(), IP, body, &state).await.unwrap() else {
        panic!("saved")
    };
    let page = Picker::new(&e).render_for(&h(), &q(&to)).await.unwrap();
    let table = workorders(&e, "").await;
    for html in [page, table] {
        assert!(!html.contains("<script>x") && html.contains("&#60;script&#62;x"), "{html}");
    }
}

#[cfg(feature = "csrf")]
#[tokio::test]
async fn an_edit_checks_csrf_like_every_write() {
    let csrf = crate::csrf::Csrf::new().secure(false);
    let jar = format!("{}={}", csrf.cookie(), "c".repeat(64));
    let (e, db) = fixture(Setup { csrf: Some(csrf), ..viewing() }).await;
    let mut headers = HeaderMap::new();
    headers.insert(http::header::COOKIE, jar.parse().unwrap());
    let state = q("pick=workorder.airline&edit=1");
    let r = Picker::new(&e).submit(&headers, IP, b"_op=update&_id=1&name=Nope&hq=1", &state).await;
    assert!(matches!(r, Err(Error::Csrf)), "{r:?}");
    let body = format!("_op=update&_id=1&name=Yes&hq=1&_csrf={}", "c".repeat(64));
    let r = Picker::new(&e).submit(&headers, IP, body.as_bytes(), &state).await;
    assert!(matches!(r, Ok(Outcome::Done(_))), "control: with the token: {r:?}");
    assert_eq!(airlines(&db).await, ["Yes"]);
}
