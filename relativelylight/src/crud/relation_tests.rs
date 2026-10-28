//! Relation reads over a real database: what a finished row's relations hold, and what they cost.
//!
//! A page resolves each relation for all its rows at once, so the number of queries depends on the
//! relations, not the rows. The counts are taken with SeaORM's metric callback, which sees every
//! statement the backend sends.

use crate::authz::Open;
use crate::crud::engine::{Engine, ListQuery, Page};
use crate::crud::seaorm::{Crud, MetaModel};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ---- entities: author 1—N post N—M tag ----

mod author {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "author")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: String,
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
        pub author_id: Option<i32>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::author::Entity",
            from = "Column::AuthorId",
            to = "super::author::Column::Id"
        )]
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

// ---- fixture ----

/// Post 3 points at an author that doesn't exist and post 4 at none; post 2 has no tags.
const SEED: &[&str] = &[
    "CREATE TABLE author (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
    "CREATE TABLE post (id INTEGER PRIMARY KEY, title TEXT NOT NULL, author_id INTEGER)",
    "CREATE TABLE tag (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
    "CREATE TABLE post_tag (post_id INTEGER NOT NULL, tag_id INTEGER NOT NULL, \
     PRIMARY KEY (post_id, tag_id))",
    "INSERT INTO author (id, name) VALUES (1, 'Ada'), (2, 'Brian'), (3, 'Nobody')",
    "INSERT INTO post (id, title, author_id) VALUES \
       (1, 'one', 1), (2, 'two', 2), (3, 'three', 99), (4, 'four', NULL), (5, 'five', 1)",
    "INSERT INTO tag (id, name) VALUES (1, 'rust'), (2, 'sql')",
    "INSERT INTO post_tag (post_id, tag_id) VALUES (1, 1), (1, 2), (3, 2), (5, 1)",
];

/// An engine over `db` (already seeded), and a counter of every statement it sends.
async fn engine(mut db: DatabaseConnection) -> (Engine, Arc<AtomicUsize>) {
    let queries = Arc::new(AtomicUsize::new(0));
    let q = queries.clone();
    db.set_metric_callback(move |_| {
        q.fetch_add(1, Ordering::SeqCst);
    });
    let a = MetaModel::new(author::Entity);
    let t = MetaModel::new(tag::Entity);
    let mut p = MetaModel::new(post::Entity);
    p.relate(&t);
    let mut crud = Crud::new(db);
    crud.register(a, Open).register(p, Open).register(t, Open);
    (crud.into_engine(), queries)
}

async fn seeded(extra: &[&str]) -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    for stmt in SEED.iter().chain(extra) {
        db.execute_unprepared(stmt).await.unwrap();
    }
    db
}

fn page(per_page: u64) -> ListQuery {
    ListQuery { page: 1, per_page, ..Default::default() }
}

fn rows(p: &Page) -> Vec<&Value> {
    p.data.iter().map(|i| i.row.as_ref().unwrap()).collect()
}

/// What `engine.list` cost, in statements.
async fn cost(engine: &Engine, queries: &AtomicUsize, slug: &str, q: &ListQuery) -> (usize, Page) {
    queries.store(0, Ordering::SeqCst);
    let p = engine.list(slug, q, false).await.unwrap();
    (queries.load(Ordering::SeqCst), p)
}

// ---- what a row holds ----

#[tokio::test]
async fn every_kind_of_relation_resolves_for_each_row_of_a_page() {
    let (engine, _) = engine(seeded(&[]).await).await;
    let p = engine.list("post", &page(10), false).await.unwrap();
    let authors: Vec<&Value> = rows(&p).iter().map(|r| &r["author"]).collect();
    assert_eq!(
        authors,
        [
            &json!({"id": 1, "label": "Ada"}),
            &json!({"id": 2, "label": "Brian"}),
            &json!({"id": 99, "label": "#99"}), // a dangling key keeps its id
            &Value::Null,
            &json!({"id": 1, "label": "Ada"}),
        ]
    );
    let tags: Vec<&Value> = rows(&p).iter().map(|r| &r["tag"]).collect();
    assert_eq!(
        tags,
        [
            &json!([{"id": 1, "label": "rust"}, {"id": 2, "label": "sql"}]),
            &json!([]),
            &json!([{"id": 2, "label": "sql"}]),
            &json!([]),
            &json!([{"id": 1, "label": "rust"}]),
        ]
    );

    let p = engine.list("author", &page(10), false).await.unwrap();
    let posts: Vec<&Value> = rows(&p).iter().map(|r| &r["post"]).collect();
    assert_eq!(
        posts,
        [
            &json!([{"id": 1, "label": "one"}, {"id": 5, "label": "five"}]),
            &json!([{"id": 2, "label": "two"}]),
            &json!([]),
        ]
    );
}

#[tokio::test]
async fn a_single_row_resolves_the_same_as_its_row_in_a_page() {
    let (engine, _) = engine(seeded(&[]).await).await;
    let p = engine.list("post", &page(10), false).await.unwrap();
    for (item, row) in p.data.iter().zip(rows(&p)) {
        let one = engine.get("post", &item.id.to_string()).await.unwrap();
        assert_eq!(&one, row);
    }
}

// ---- what a page costs ----

/// The positive control is the first assertion: the counter does see the queries.
#[tokio::test]
async fn a_pages_query_count_does_not_grow_with_its_rows() {
    // 200 more posts, each by its own new author and with both tags.
    let extra = [
        "WITH RECURSIVE n(i) AS (SELECT 10 UNION ALL SELECT i + 1 FROM n WHERE i < 209) \
         INSERT INTO author (id, name) SELECT i, 'a' || i FROM n",
        "WITH RECURSIVE n(i) AS (SELECT 10 UNION ALL SELECT i + 1 FROM n WHERE i < 209) \
         INSERT INTO post (id, title, author_id) SELECT i, 'p' || i, i FROM n",
        "INSERT INTO post_tag (post_id, tag_id) SELECT id, 1 FROM post WHERE id >= 10 \
         UNION ALL SELECT id, 2 FROM post WHERE id >= 10",
    ];
    let (engine, queries) = engine(seeded(&extra).await).await;

    let (small, p) = cost(&engine, &queries, "post", &page(2)).await;
    assert_eq!(p.data.len(), 2);
    assert!(small > 0, "the counter saw nothing, so the comparison below would pass vacuously");
    let (large, p) = cost(&engine, &queries, "post", &page(200)).await;
    assert_eq!(p.data.len(), 200);
    assert_eq!(large, small, "a page of 200 cost {large} queries, a page of 2 cost {small}");
    // count + page + one per relation (author, tag)
    assert_eq!(small, 4);

    let (authors, _) = cost(&engine, &queries, "author", &page(200)).await;
    assert_eq!(authors, 3, "count + page + the inverse posts");
}

/// An `IN (…)` list is split, so an unpaginated listing of a large table neither builds one
/// enormous statement nor loses the rows past the split.
#[tokio::test]
async fn an_unpaginated_listing_resolves_past_the_in_list_chunk() {
    let extra = [
        "WITH RECURSIVE n(i) AS (SELECT 10 UNION ALL SELECT i + 1 FROM n WHERE i < 1209) \
         INSERT INTO author (id, name) SELECT i, 'a' || i FROM n",
        "WITH RECURSIVE n(i) AS (SELECT 10 UNION ALL SELECT i + 1 FROM n WHERE i < 1209) \
         INSERT INTO post (id, title, author_id) SELECT i, 'p' || i, i FROM n",
    ];
    let (engine, queries) = engine(seeded(&extra).await).await;
    let (n, p) = cost(&engine, &queries, "post", &ListQuery { all: true, ..Default::default() }).await;
    assert_eq!(p.data.len(), 1205);
    for r in rows(&p).iter().filter(|r| r["id"].as_i64().unwrap() >= 10) {
        assert_eq!(r["author"]["label"], format!("a{}", r["id"]));
    }
    // the rows + three chunks of authors + three of tags
    assert_eq!(n, 7);
}

// ---- the inverse cap ----

#[tokio::test]
async fn a_long_inverse_list_is_cut_and_says_how_many_it_left_out() {
    let extra = [
        "WITH RECURSIVE n(i) AS (SELECT 10 UNION ALL SELECT i + 1 FROM n WHERE i < 114) \
         INSERT INTO post (id, title, author_id) SELECT i, 'p' || i, 2 FROM n",
    ];
    let (engine, _) = engine(seeded(&extra).await).await;

    let p = engine.list("author", &page(10), false).await.unwrap();
    let brian = rows(&p)[1]["post"].as_array().unwrap().clone();
    assert_eq!(brian.len(), 101);
    assert_eq!(brian[0], json!({"id": 2, "label": "two"}));
    assert_eq!(brian[100], json!({"more": 6}));
    assert_eq!(engine.get("author", "2").await.unwrap()["post"], Value::Array(brian));

    // The CSV export asks for everything, and gets every link.
    let all = engine.list("author", &ListQuery { all: true, ..Default::default() }, false).await.unwrap();
    assert_eq!(rows(&all)[1]["post"].as_array().unwrap().len(), 106);
    // Below the cap, nothing is added.
    assert_eq!(rows(&p)[0]["post"].as_array().unwrap().len(), 2);

    let html = crate::crud::ui::Table::new(&engine, "author")
        .render_for(&axum::http::HeaderMap::new(), &crate::crud::ui::ViewState::default())
        .await
        .unwrap();
    assert!(html.contains(">+6 more</span>"), "the cut is shown, not hidden");
}
