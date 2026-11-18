//! A column's transforms, end to end over a real database: typed text → the engine → storage, and
//! back. A stub accessor can't show any of this — `blank_is_null` and `on_read`/`on_write` live in the
//! SeaORM backend — and every bug here was a disagreement *between* layers that each looked right.
//!
//! - The form's decoder and CSV import read typed text through one function (`crud::text`), so an
//!   empty input and an empty cell mean the same thing.
//! - `on_read` / `on_write` are an inverse pair: the edit form is filled from `on_read`'s output, so
//!   saving an untouched form stores exactly what was there.

use crate::authz::Open;
use crate::crud::engine::Engine;
use crate::crud::seaorm::{Crud, MetaModel};
use crate::crud::ui::{Form, Outcome, ViewState};
use http::HeaderMap;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

mod contact {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "contact")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: String,
        pub nickname: Option<String>,
        pub rank: Option<i32>,
        /// Stored as digits; shown and typed as `+420 123 456 789`.
        pub phone: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

/// A row that must belong to a contact: a NOT NULL to-one.
mod note {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "note")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub text: String,
        pub contact_id: i32,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(belongs_to = "super::contact::Entity", from = "Column::ContactId", to = "super::contact::Column::Id")]
        Contact,
    }
    impl Related<super::contact::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Contact.def()
        }
    }
    impl ActiveModelBehavior for ActiveModel {}
}

async fn db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    for stmt in [
        "CREATE TABLE contact (id INTEGER PRIMARY KEY, name TEXT NOT NULL, nickname TEXT, rank INTEGER, \
         phone TEXT NOT NULL)",
        "INSERT INTO contact (id, name, nickname, rank, phone) VALUES (1, 'Ada', 'ada', 3, '420123456789')",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
    db
}

/// The engine over `db`, with `configure` applied to the model first.
fn engine(db: &DatabaseConnection, configure: impl FnOnce(&mut MetaModel<contact::Entity>)) -> Engine {
    let mut m = MetaModel::new(contact::Entity);
    configure(&mut m);
    let mut crud = Crud::new(db.clone());
    crud.register(m, Open);
    crud.into_engine()
}

/// What the database holds for contact 1 — under the transforms, not through them.
async fn stored(db: &DatabaseConnection) -> Value {
    let row = db
        .query_one_raw(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "SELECT nickname, rank, phone FROM contact WHERE id = 1",
        ))
        .await
        .unwrap()
        .unwrap();
    json!({
        "nickname": row.try_get::<Option<String>>("", "nickname").unwrap(),
        "rank": row.try_get::<Option<i32>>("", "rank").unwrap(),
        "phone": row.try_get::<String>("", "phone").unwrap(),
    })
}

/// Save contact 1's edit form with `fields` — the hidden inputs the form renders, then these.
async fn save(e: &Engine, fields: &str) {
    let form = Form::new(e, "contact").edit("1");
    let body = format!("_op=update&_id=1&{fields}");
    match form.submit(&HeaderMap::new(), IP, body.as_bytes(), &ViewState::default()).await.unwrap() {
        Outcome::Done(_) => {}
        Outcome::Invalid(s) => panic!("rejected: {:?}", s.field_error("phone")),
    }
}

/// `+420 123 456 789` ↔ `420123456789` — a codec, not a display rule: each undoes the other.
fn phone_codec(m: &mut MetaModel<contact::Entity>) {
    m.field("phone").on_read = Some(Box::new(|v| {
        let d = v.as_str().unwrap_or_default();
        match d.len() {
            12 => json!(format!("+{} {} {} {}", &d[..3], &d[3..6], &d[6..9], &d[9..])),
            _ => v.clone(),
        }
    }));
    m.field("phone").on_write = Some(Box::new(|v| {
        json!(v.as_str().unwrap_or_default().chars().filter(char::is_ascii_digit).collect::<String>())
    }));
}

#[tokio::test]
async fn a_blank_input_honours_blank_is_null_both_ways() {
    // Default: a blank nullable text input is stored as NULL.
    let db = db().await;
    let e = engine(&db, |_| {});
    save(&e, "name=Ada&nickname=&rank=3&phone=420123456789").await;
    assert_eq!(stored(&db).await["nickname"], Value::Null);

    // Switched off, it is the empty string. The form used to send `null` for any blank nullable
    // input, so this setting did nothing through a form — only the engine's own callers saw it.
    let db = self::db().await;
    let e = engine(&db, |m| m.field("nickname").blank_is_null = false);
    save(&e, "name=Ada&nickname=&rank=3&phone=420123456789").await;
    assert_eq!(stored(&db).await["nickname"], json!(""));
}

#[tokio::test]
async fn an_untouched_edit_form_saves_what_was_stored() {
    let db = db().await;
    let e = engine(&db, phone_codec);
    // The form is filled from `on_read`'s output, as every read is…
    let html = Form::new(&e, "contact").edit("1").render_for(&HeaderMap::new(), &ViewState::default()).await.unwrap();
    assert!(html.contains(r#"value="+420 123 456 789""#), "{html}");
    // …so submitting it as shown goes back through `on_write` to the same stored value.
    save(&e, "name=Ada&nickname=ada&rank=3&phone=%2B420+123+456+789").await;
    assert_eq!(stored(&db).await["phone"], json!("420123456789"));
}

#[cfg(feature = "csv")]
#[tokio::test]
async fn a_csv_cell_means_what_a_form_input_does() {
    use crate::crud::csv_io;
    use crate::crud::engine::ListQuery;
    use crate::time::Tz;

    let db = db().await;
    let e = engine(&db, phone_codec);
    let cols = e.columns("contact").unwrap();

    // The export carries the logical value, and re-importing it stores the original.
    let file = csv_io::export(&e, "contact", &cols, &ListQuery::default(), &Tz::UTC).await.unwrap();
    assert!(file.contains("+420 123 456 789"), "{file}");
    let report = csv_io::import(&e, "contact", &cols, &file, &Tz::UTC).await.unwrap();
    assert_eq!((report.updated, report.failed), (1, 0), "{:?}", report.errors);
    assert_eq!(stored(&db).await, json!({"nickname": "ada", "rank": 3, "phone": "420123456789"}));

    // Blank cells: a nullable number is cleared, as a blank form input clears it — the import used to
    // leave it alone — and a nullable text follows `blank_is_null`.
    let blanked = "id,name,nickname,rank,phone\n1,Ada,,,420123456789\n";
    let report = csv_io::import(&e, "contact", &cols, blanked, &Tz::UTC).await.unwrap();
    assert_eq!(report.failed, 0, "{:?}", report.errors);
    assert_eq!(stored(&db).await, json!({"nickname": null, "rank": null, "phone": "420123456789"}));

    // Positive control for the form path: the same blanks, typed.
    let db = self::db().await;
    let e = engine(&db, phone_codec);
    save(&e, "name=Ada&nickname=&rank=&phone=420123456789").await;
    assert_eq!(stored(&db).await, json!({"nickname": null, "rank": null, "phone": "420123456789"}));
}

#[tokio::test]
async fn a_blank_required_relation_is_a_field_error_not_a_panic() {
    let db = db().await;
    for stmt in [
        "CREATE TABLE note (id INTEGER PRIMARY KEY, text TEXT NOT NULL, contact_id INTEGER NOT NULL)",
        "INSERT INTO note (id, text, contact_id) VALUES (1, 'hi', 1)",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
    let mut crud = Crud::new(db.clone());
    crud.register(MetaModel::new(contact::Entity), Open);
    crud.register(MetaModel::new(note::Entity), Open);
    let e = crud.into_engine();
    let submit = |body: &'static str| {
        let e = &e;
        async move {
            // The form a page would build for this post: `.edit` for an update.
            let form = match body.contains("_op=update&_id=1") {
                true => Form::new(e, "note").edit("1"),
                false => Form::new(e, "note"),
            };
            form.submit(&HeaderMap::new(), IP, body.as_bytes(), &ViewState::default()).await
        }
    };

    // SeaORM 2.0's `ActiveModel::set` panics on a null for an `i32` column; these used to reach it.
    for body in ["_op=create&text=t&contact=", "_op=create&text=t", "_op=update&_id=1&text=t&contact="] {
        match submit(body).await {
            Ok(Outcome::Invalid(s)) => assert_eq!(s.field_error("contact"), Some("required"), "{body}"),
            other => panic!("{body}: expected a field error, got {other:?}"),
        }
    }
    // Positive control: given, it saves.
    assert!(matches!(submit("_op=create&text=t&contact=1").await, Ok(Outcome::Done(_))));
}

/// A `db_type = "Enum"` column on **SQLite**: the entity reports `ColumnType::Enum`, so the variants
/// are introspected, while SQLite stores plain text (sea-query only casts to the enum type on
/// Postgres). The table is created as `TEXT`, the way an existing SQLite schema has it.
mod ticket {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    /// Serde names match the `string_value`s: the engine reads rows through `Serialize`.
    #[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
    #[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "ticket_state")]
    #[serde(rename_all = "snake_case")]
    pub enum State {
        #[sea_orm(string_value = "open")]
        Open,
        #[sea_orm(string_value = "in_review")]
        InReview,
        #[sea_orm(string_value = "closed")]
        Closed,
    }

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "ticket")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub state: State,
        pub previous: Option<State>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[tokio::test]
async fn an_enum_column_round_trips_on_sqlite() {
    use crate::crud::engine::{Column, ListQuery};

    let db = Database::connect("sqlite::memory:").await.unwrap();
    for stmt in [
        "CREATE TABLE ticket (id INTEGER PRIMARY KEY, state TEXT NOT NULL, previous TEXT)",
        "INSERT INTO ticket (id, state, previous) VALUES (1, 'in_review', 'open')",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
    let mut crud = Crud::new(db.clone());
    crud.register(MetaModel::new(ticket::Entity), Open);
    let e = crud.into_engine();
    let stored = |id: i32| {
        let db = db.clone();
        async move {
            let row = db
                .query_one_raw(sea_orm::Statement::from_string(
                    db.get_database_backend(),
                    format!("SELECT state, previous FROM ticket WHERE id = {id}"),
                ))
                .await
                .unwrap()
                .unwrap();
            (row.try_get::<String>("", "state").unwrap(), row.try_get::<Option<String>>("", "previous").unwrap())
        }
    };

    // Introspected, with nothing declared.
    let options: Vec<Vec<String>> = e
        .columns("ticket")
        .unwrap()
        .into_iter()
        .filter_map(|c| match c {
            Column::Field { name, options, .. } if name == "state" => Some(options),
            _ => None,
        })
        .collect();
    assert_eq!(options, vec![vec!["open".to_string(), "in_review".into(), "closed".into()]]);

    // The edit form is a dropdown with the stored value chosen.
    let html = Form::new(&e, "ticket").edit("1").render_for(&HeaderMap::new(), &ViewState::default()).await.unwrap();
    assert!(html.contains(r#"<option value="in_review" selected>"#), "{html}");

    let submit = |body: &'static str| {
        let e = &e;
        async move {
            // The form a page would build for this post: `.edit` for an update.
            let form = match body.contains("_op=update&_id=1") {
                true => Form::new(e, "ticket").edit("1"),
                false => Form::new(e, "ticket"),
            };
            form.submit(&HeaderMap::new(), IP, body.as_bytes(), &ViewState::default()).await
        }
    };
    // Writes store the string value, and a nullable enum clears to NULL.
    assert!(matches!(submit("_op=update&_id=1&state=closed&previous=").await, Ok(Outcome::Done(_))));
    assert_eq!(stored(1).await, ("closed".to_string(), None));
    assert!(matches!(submit("_op=create&state=open&previous=in_review").await, Ok(Outcome::Done(_))));
    assert_eq!(stored(2).await, ("open".to_string(), Some("in_review".to_string())));

    // A Rust variant name is not a value.
    match submit("_op=create&state=InReview").await {
        Ok(Outcome::Invalid(s)) => {
            assert_eq!(s.field_error("state"), Some("must be one of: open, in_review, closed"))
        }
        other => panic!("expected a field error, got {other:?}"),
    }

    // Filtering compares against the stored text.
    let q = ListQuery { eq: vec![("state".into(), "open".into())], per_page: 10, ..Default::default() };
    let page = e.list("ticket", &q, false).await.unwrap();
    assert_eq!(page.data.iter().map(|r| r.id.clone()).collect::<Vec<_>>(), vec![json!(2)]);
}

/// A calendar date, an instant as integer seconds, and a native timestamp — the three ways a model
/// holds time (`docs/TIME.md` §1).
mod dated {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "dated")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub issued_on: Date,
        pub due_on: Option<Date>,
        pub sent_at: Option<ChronoUnixTimestamp>,
        pub logged: Option<DateTime>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[tokio::test]
async fn dates_are_written_in_one_form_and_instants_as_seconds() {
    use crate::crud::engine::{Column, ListQuery};

    let db = Database::connect("sqlite::memory:").await.unwrap();
    for stmt in [
        "CREATE TABLE dated (id INTEGER PRIMARY KEY, issued_on date_text NOT NULL, due_on date_text, \
         sent_at INTEGER, logged datetime_text)",
        "INSERT INTO dated (id, issued_on, due_on, sent_at, logged) \
         VALUES (1, '2026-11-05', NULL, 1793795400, '2026-11-05 12:30:00')",
    ] {
        db.execute_unprepared(stmt).await.unwrap();
    }
    let mut m = MetaModel::new(dated::Entity);
    m.field("sent_at").datetime();
    let mut crud = Crud::new(db.clone());
    crud.register(m, Open);
    let e = crud.into_engine();
    let stored = |id: i32| {
        let db = db.clone();
        async move {
            let row = db
                .query_one_raw(sea_orm::Statement::from_string(
                    db.get_database_backend(),
                    format!("SELECT issued_on, due_on, sent_at, logged FROM dated WHERE id = {id}"),
                ))
                .await
                .unwrap()
                .map(|r| {
                    json!([
                        r.try_get::<String>("", "issued_on").unwrap(),
                        r.try_get::<Option<String>>("", "due_on").unwrap(),
                        r.try_get::<Option<i64>>("", "sent_at").unwrap(),
                        r.try_get::<Option<String>>("", "logged").unwrap(),
                    ])
                });
            row.unwrap_or(Value::Null)
        }
    };
    let submit = |body: String| {
        let e = &e;
        async move {
            let form = match body.contains("_op=update&_id=1") {
                true => Form::new(e, "dated").edit("1"),
                false => Form::new(e, "dated"),
            };
            form.submit(&HeaderMap::new(), IP, body.as_bytes(), &ViewState::default()).await
        }
    };

    // The native timestamp is introspected read-only; the date and the instant are inputs.
    let read_only: Vec<String> = e
        .columns("dated")
        .unwrap()
        .into_iter()
        .filter_map(|c| match c {
            Column::Field { name, read_only: true, .. } => Some(name),
            _ => None,
        })
        .collect();
    assert_eq!(read_only, vec!["id".to_string(), "logged".into()]);
    let html = Form::new(&e, "dated").edit("1").render_for(&HeaderMap::new(), &ViewState::default()).await.unwrap();
    assert!(html.contains(r#"type="date" name="issued_on" value="2026-11-05""#), "{html}");
    assert!(html.contains(r#"type="datetime-local""#), "{html}");
    assert!(!html.contains(r#"name="logged""#), "{html}");

    // A date in the one canonical form is stored as exactly that text; an instant as its seconds
    // (the form's wall clock read in the viewer's zone — UTC here); a blank nullable date is NULL.
    let ok = submit("_op=create&issued_on=2026-02-28&due_on=&sent_at=2026-11-05T12%3A30".into()).await;
    assert!(matches!(ok, Ok(Outcome::Done(_))), "{ok:?}");
    assert_eq!(stored(2).await, json!(["2026-02-28", null, 1793881800, null])); // 2026-11-05 12:30 UTC

    // Anything else is a field error, and nothing is written: SQLite would have stored any of these
    // as text, and sorted and range-filtered them wrongly ever after.
    for bad in ["5.11.2026", "2026-1-5", "2026-02-30", "2026-11-05T00:00", "26-11-05"] {
        match submit(format!("_op=create&issued_on={bad}")).await {
            Ok(Outcome::Invalid(s)) => {
                assert_eq!(s.field_error("issued_on"), Some("expected a date, YYYY-MM-DD"), "{bad}")
            }
            other => panic!("{bad}: expected a field error, got {other:?}"),
        }
    }
    // A blank required date is "required", as any other required field.
    match submit("_op=create&issued_on=".into()).await {
        Ok(Outcome::Invalid(s)) => assert_eq!(s.field_error("issued_on"), Some("required")),
        other => panic!("expected a field error, got {other:?}"),
    }
    assert_eq!(stored(3).await, Value::Null);

    // An update clears the nullable date and keeps the native timestamp it can't write.
    assert!(matches!(
        submit("_op=update&_id=1&issued_on=2026-11-06&due_on=&sent_at=".into()).await,
        Ok(Outcome::Done(_))
    ));
    assert_eq!(stored(1).await, json!(["2026-11-06", null, null, "2026-11-05 12:30:00"]));
    // The engine refuses a native date-time a caller marked writable, saying why.
    let mut m = MetaModel::new(dated::Entity);
    m.field("logged").read_only = false;
    let mut crud = Crud::new(db.clone());
    crud.register(m, Open);
    let e2 = crud.into_engine();
    match Form::new(&e2, "dated")
        .submit(&HeaderMap::new(), IP, b"_op=create&issued_on=2026-01-01&logged=2026-01-01T10%3A00", &ViewState::default())
        .await
    {
        Ok(Outcome::Invalid(s)) => assert!(s.field_error("logged").unwrap().contains("Unix seconds")),
        other => panic!("expected a field error, got {other:?}"),
    }

    // Filters and ranges compare dates as dates, and sort in calendar order.
    let ids = |q: ListQuery| {
        let e = &e;
        async move {
            let page = e.list("dated", &ListQuery { per_page: 10, ..q }, false).await.unwrap();
            page.data.iter().map(|r| r.id.clone()).collect::<Vec<_>>()
        }
    };
    assert_eq!(ids(ListQuery { eq: vec![("issued_on".into(), "2026-02-28".into())], ..Default::default() }).await, vec![json!(2)]);
    assert_eq!(ids(ListQuery { eq: vec![("issued_on".into(), "garbage".into())], ..Default::default() }).await, Vec::<Value>::new());
    // Both rows have no `due_on` now: a malformed date must not match them as "no date" would.
    let due = |v: &str| ListQuery { eq: vec![("due_on".into(), v.into())], ..Default::default() };
    assert_eq!(ids(due("garbage")).await, Vec::<Value>::new(), "a malformed date matches nothing");
    assert_eq!(ids(due("")).await, vec![json!(1), json!(2)], "control: the empty filter finds them");
    let range = |from: &str, to: &str| ListQuery {
        range: vec![("issued_on".into(), Some(from.into()), Some(to.into()))],
        ..Default::default()
    };
    assert_eq!(ids(range("2026-11-01", "2026-11-30")).await, vec![json!(1)]);
    assert_eq!(ids(range("2026-01-01", "2026-12-31")).await.len(), 2);
    let sorted = ListQuery { sort: vec![("issued_on".into(), false)], ..Default::default() };
    assert_eq!(ids(sorted).await, vec![json!(2), json!(1)]);
    // A native date-time sorts, but has no range control: an instant is ranged as integer seconds.
    let ranged = |col: &'static str| crate::crud::ui::Table::new(&e, "dated").range_filter(col);
    let err = ranged("logged").render_for(&HeaderMap::new(), &ViewState::default()).await.unwrap_err();
    assert!(matches!(&err, crate::crud::Error::BadRequest(m) if m.contains("'logged'")), "{err}");
    ranged("issued_on").render_for(&HeaderMap::new(), &ViewState::default()).await.expect("control: a date ranges");

    // CSV: a date leaves as the text it is and comes back as the same date. The file carries the
    // read-only native timestamp too, which the import leaves alone; a malformed date in a cell is
    // that row's error, as on the form.
    #[cfg(feature = "csv")]
    {
        use crate::crud::csv_io;
        use crate::time::Tz;
        let cols = e.columns("dated").unwrap();
        let file = csv_io::export(&e, "dated", &cols, &ListQuery::default(), &Tz::UTC).await.unwrap();
        assert!(file.contains("2026-11-06") && file.contains("2026-02-28"), "{file}");
        let before = (stored(1).await, stored(2).await);
        let report = csv_io::import(&e, "dated", &cols, &file, &Tz::UTC).await.unwrap();
        assert_eq!((report.updated, report.failed), (2, 0), "{:?}", report.errors);
        assert_eq!((stored(1).await, stored(2).await), before, "the round trip changes nothing");
        let bad = "id,issued_on\n1,5.11.2026\n";
        let report = csv_io::import(&e, "dated", &cols, bad, &Tz::UTC).await.unwrap();
        assert_eq!(report.failed, 1, "{:?}", report.errors);
        assert!(report.errors[0].message.contains("YYYY-MM-DD"), "{:?}", report.errors);
        assert_eq!(stored(1).await, before.0, "and nothing was written");
    }
}
