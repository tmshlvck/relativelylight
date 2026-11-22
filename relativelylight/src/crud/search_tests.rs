//! The search box over a real database (CRUD.md → Search): one term matched, as printed, against
//! everything a table shows — text, numbers, dates, choices by their label, instants by the period a
//! term names, the row's own label and each relation's labels — and against nothing it hides.

use crate::authz::Open;
use crate::crud::engine::{Engine, ListQuery};
use crate::crud::seaorm::{Crud, MetaModel};
use sea_orm::{ConnectionTrait, Database};
use serde_json::Value;

mod author {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "author")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub first_name: String,
        pub last_name: String,
        pub born_on: Option<Date>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(has_many = "super::post::Entity")]
        Post,
    }
    impl Related<super::post::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Post.def()
        }
    }
    impl ActiveModelBehavior for ActiveModel {}
}

mod post {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "post")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub title: String,
        pub views: i32,
        pub rating: Option<f64>,
        pub status: String,
        pub secret: String,
        pub notes: String,
        pub published_at: Option<i64>,
        pub author_id: Option<i32>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(belongs_to = "super::author::Entity", from = "Column::AuthorId", to = "super::author::Column::Id")]
        Author,
    }
    impl Related<super::author::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Author.def()
        }
    }
    impl Related<super::tag::Entity> for Entity {
        fn to() -> RelationDef {
            super::post_tag::Relation::Tag.def()
        }
        fn via() -> Option<RelationDef> {
            Some(super::post_tag::Relation::Post.def().rev())
        }
    }
    impl ActiveModelBehavior for ActiveModel {}
}

mod tag {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "tag")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub kind: String,
        pub name: String,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod post_tag {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "post_tag")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub post_id: i32,
        #[sea_orm(primary_key, auto_increment = false)]
        pub tag_id: i32,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(belongs_to = "super::post::Entity", from = "Column::PostId", to = "super::post::Column::Id")]
        Post,
        #[sea_orm(belongs_to = "super::tag::Entity", from = "Column::TagId", to = "super::tag::Column::Id")]
        Tag,
    }
    impl ActiveModelBehavior for ActiveModel {}
}

const SEED: &[&str] = &[
    "CREATE TABLE author (id INTEGER PRIMARY KEY, first_name TEXT NOT NULL, last_name TEXT NOT NULL, born_on TEXT)",
    "CREATE TABLE post (id INTEGER PRIMARY KEY, title TEXT NOT NULL, views INTEGER NOT NULL, rating REAL, \
     status TEXT NOT NULL, secret TEXT NOT NULL, notes TEXT NOT NULL, published_at BIGINT, author_id INTEGER)",
    "CREATE TABLE tag (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL)",
    "CREATE TABLE post_tag (post_id INTEGER NOT NULL, tag_id INTEGER NOT NULL, PRIMARY KEY (post_id, tag_id))",
    "INSERT INTO author VALUES (1, 'Jan', 'Novak', '1980-05-17'), (2, 'Eva', 'Svoboda', '1975-03-05')",
    // published: 2026-03-05 10:00 UTC, 2026-04-10 12:00 UTC, none.
    "INSERT INTO post VALUES \
       (1, 'Engines', 1234, 4.5, 'review', 'zzsecret', 'a quiet note', 1772704800, 1), \
       (2, 'Wings', 77, 3.0, 'draft', 'zzsecret', '', 1775822400, 2), \
       (3, 'Tails 100%_', 5, NULL, 'draft', '', '', NULL, NULL)",
    "INSERT INTO tag VALUES (1, 'topic', 'rust'), (2, 'area', 'Prague')",
    "INSERT INTO post_tag VALUES (1, 1), (2, 2)",
];

async fn engine(configure: impl FnOnce(&mut MetaModel<post::Entity>)) -> Engine {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    for stmt in SEED {
        db.execute_unprepared(stmt).await.unwrap();
    }
    let mut a = MetaModel::new(author::Entity);
    a.label_columns(["first_name", "last_name"], " ");
    let mut t = MetaModel::new(tag::Entity);
    t.label_columns(["kind", "name"], ": ");
    let mut p = MetaModel::new(post::Entity);
    p.label_column("title");
    p.relate(&t);
    p.field("secret").hidden = true;
    p.field("notes").searchable = false;
    p.field("published_at").datetime();
    p.field("status").options = vec!["draft".into(), "review".into()];
    p.field("status").option_labels = vec![("review".into(), "In review".into())];
    configure(&mut p);
    let mut crud = Crud::new(db);
    crud.register(a, Open).register(p, Open).register(t, Open);
    crud.into_engine()
}

/// The ids of `slug`'s rows `term` finds (with `period`, as the table passes it).
async fn found(e: &Engine, slug: &str, term: &str, period: Option<(i64, i64)>) -> Vec<i64> {
    let q = ListQuery { search: vec![(None, term.into())], search_period: period, per_page: 50, ..Default::default() };
    let page = e.list(slug, &q, false).await.unwrap();
    page.data.iter().map(|r| r.id.as_i64().unwrap()).collect()
}

#[tokio::test]
async fn a_term_matches_what_the_row_shows() {
    let e = engine(|_| {}).await;
    let posts = |t: &'static str| {
        let e = &e;
        async move { found(e, "post", t, None).await }
    };
    assert_eq!(posts("engi").await, [1], "text, any case");
    assert_eq!(posts("ENGINES").await, [1]);
    assert_eq!(posts("123").await, [1], "a number, as a substring of how it prints");
    assert_eq!(posts("4.5").await, [1], "a decimal");
    assert_eq!(posts("in rev").await, [1], "a choice by its label");
    assert_eq!(posts("draft").await, [2, 3], "and by its value");
    assert_eq!(posts("100%_").await, [3], "the term is literal: `%` and `_` are no wildcards");
    assert_eq!(posts("%").await, [3]);
    assert_eq!(posts("nothing like it").await, Vec::<i64>::new());
}

#[tokio::test]
async fn hidden_and_opted_out_fields_are_never_searched() {
    let e = engine(|_| {}).await;
    assert_eq!(found(&e, "post", "zzsecret", None).await, Vec::<i64>::new(), "hidden");
    assert_eq!(found(&e, "post", "quiet note", None).await, Vec::<i64>::new(), "searchable = false");
    // Control: switched back on, the same note is found.
    let e = engine(|p| p.field("notes").searchable = true).await;
    assert_eq!(found(&e, "post", "quiet note", None).await, [1]);
}

#[tokio::test]
async fn relations_match_by_their_labels_as_shown() {
    let e = engine(|_| {}).await;
    assert_eq!(found(&e, "post", "Jan Novak", None).await, [1], "to-one, a label of two columns");
    assert_eq!(found(&e, "post", "novak", None).await, [1]);
    assert_eq!(found(&e, "post", "topic: rust", None).await, [1], "N:M, with its separator");
    assert_eq!(found(&e, "post", "prague", None).await, [2]);
    assert_eq!(found(&e, "author", "wings", None).await, [2], "the other side of a to-many");
    assert_eq!(found(&e, "author", "Jan Novak", None).await, [1], "the row's own label");
    assert_eq!(found(&e, "author", "1980-05", None).await, [1], "a calendar date as printed");
    // Opted out, the author's name finds nothing.
    let e = engine(|p| p.relation("author").searchable = false).await;
    assert_eq!(found(&e, "post", "Novak", None).await, Vec::<i64>::new());
}

#[cfg(feature = "tz")]
#[tokio::test]
async fn an_instant_matches_when_the_term_names_its_period() {
    use crate::time::Tz;
    let e = engine(|_| {}).await;
    let (utc, tokyo) = (Tz::UTC, Tz::named("Asia/Tokyo"));
    assert_eq!(found(&e, "post", "2026-03", utc.period("2026-03")).await, [1]);
    assert_eq!(found(&e, "post", "2026", utc.period("2026")).await, [1, 2]);
    // 10:00 UTC is 19:00 in Tokyo: the hour is the viewer's.
    assert_eq!(found(&e, "post", "2026-03-05 19", tokyo.period("2026-03-05 19")).await, [1]);
    assert_eq!(found(&e, "post", "2026-03-05 19", utc.period("2026-03-05 19")).await, Vec::<i64>::new());
    // Not a period: the instants are left out, nothing else changes.
    assert_eq!(found(&e, "post", "03-05", None).await, Vec::<i64>::new());
}

#[cfg(feature = "ui")]
#[tokio::test]
async fn the_table_reads_the_period_in_the_viewers_zone() {
    use crate::crud::ui::{Table, ViewState};
    let e = engine(|_| {}).await;
    let mut tokyo = http::HeaderMap::new();
    tokyo.insert(http::header::COOKIE, "rl_tz=Asia%2FTokyo".parse().unwrap());
    let titles = |html: &str| ["Engines", "Wings"].into_iter().filter(|t| html.contains(&format!("<td>{t}"))).collect::<Vec<_>>();
    let table = Table::new(&e, "post");
    let html = table.render_for(&tokyo, &ViewState::from_query("q=2026-03-05+19")).await.unwrap();
    assert_eq!(titles(&html), ["Engines"]);
    let html = table.render_for(&http::HeaderMap::new(), &ViewState::from_query("q=2026-03-05+19")).await.unwrap();
    assert_eq!(titles(&html), Vec::<&str>::new(), "the same hour in UTC is another");
}

#[tokio::test]
async fn a_relation_sorts_by_its_label_columns_in_turn() {
    let e = engine(|_| {}).await;
    let q = ListQuery { sort: vec![("author".into(), false)], per_page: 50, ..Default::default() };
    let page = e.list("post", &q, false).await.unwrap();
    let ids: Vec<i64> = page.data.iter().map(|r| r.id.as_i64().unwrap()).collect();
    // Eva Svoboda before Jan Novak (first names first), the post with no author last.
    assert_eq!(ids, [2, 1, 3]);
    let label = |row: &Value| row["author"]["label"].as_str().map(String::from);
    assert_eq!(label(page.data[0].row.as_ref().unwrap()).as_deref(), Some("Eva Svoboda"), "shown joined");
}
