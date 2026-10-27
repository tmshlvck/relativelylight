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
            Form::new(e, "note").submit(&HeaderMap::new(), IP, body.as_bytes(), &ViewState::default()).await
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
