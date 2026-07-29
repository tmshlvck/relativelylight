//! Example domain model + a helper to spin up a seeded in-memory SQLite database.
//! The `relativelylight` library knows nothing about any of this.

pub mod entities {
    pub mod author;
    pub mod post;
    pub mod post_tag;
    pub mod profile;
    pub mod tag;
    pub mod user;
}

pub use entities::{author, post, post_tag, profile, tag, user};

use sea_orm::{
    ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbErr,
    EntityTrait, Schema, Set,
};
use std::time::Duration;

/// Connect to an in-memory SQLite DB, create the schema from the entities, and seed data.
///
/// **The pool is pinned to one permanent connection on purpose.** An in-memory SQLite database lives
/// *inside* its connection, and a pool recycles connections — SeaORM defaults to a 30-minute
/// `max_lifetime` and a 10-minute `idle_timeout`. When the pool closes the connection holding the
/// database, the database goes with it, and the next query fails with `no such table: post`. So an
/// example left open for half an hour would lose its data, which looked like a bug in the library and
/// was a bug in this function.
///
/// A second connection would be just as bad: with plain `sqlite::memory:` each one gets its **own**
/// empty database, so whichever request landed on it would see no tables. `max_connections(1)` avoids
/// both, and the long lifetimes stop the one connection being retired underneath us. (A real app points
/// at a file or a server and needs none of this.)
pub async fn setup() -> Result<DatabaseConnection, DbErr> {
    const FOREVER: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);
    let mut opt = ConnectOptions::new("sqlite::memory:".to_owned());
    opt.max_connections(1)
        .min_connections(1)
        .idle_timeout(FOREVER)
        .max_lifetime(FOREVER);
    let db = Database::connect(opt).await?;
    create_table(&db, author::Entity).await?;
    create_table(&db, post::Entity).await?;
    create_table(&db, user::Entity).await?;
    create_table(&db, profile::Entity).await?;
    create_table(&db, tag::Entity).await?;
    create_table(&db, post_tag::Entity).await?;
    seed(&db).await?;
    Ok(db)
}

async fn create_table<E: EntityTrait>(db: &DatabaseConnection, e: E) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let stmt = Schema::new(backend).create_table_from_entity(e);
    db.execute(backend.build(&stmt)).await?;
    Ok(())
}

async fn seed(db: &DatabaseConnection) -> Result<(), DbErr> {
    // The last author is left without contact details, so the nullable columns show both states.
    let authors = [
        ("Ada Lovelace", "UK", Some("ada@example.com"), Some("https://example.com/ada")),
        ("Bjarne Stroustrup", "DK", Some("bjarne@example.com"), None),
        ("Grace Hopper", "US", Some("grace@example.com"), Some("https://example.com/grace")),
        ("Linus Torvalds", "FI", Some("linus@example.com"), None),
        ("Barbara Liskov", "US", Some("barbara@example.com"), Some("https://example.com/liskov")),
        ("Alan Kay", "US", None, None),
    ];
    for (i, (name, country, email, homepage)) in authors.iter().enumerate() {
        author::ActiveModel {
            id: Set(i as i32 + 1),
            name: Set((*name).into()),
            country: Set((*country).into()),
            email: Set(email.map(Into::into)),
            homepage: Set(homepage.map(Into::into)),
        }
        .insert(db)
        .await?;
    }

    // A biggish tag list (40) so the N:M form widget crosses the default picker threshold (20)
    // and demonstrates the live search→select combobox.
    let tags = [
        "rust", "systems", "beginner", "async", "web", "database", "testing", "performance",
        "macros", "traits", "lifetimes", "ownership", "borrowing", "concurrency", "wasm", "cli",
        "embedded", "networking", "security", "serialization", "parsing", "graphics", "gamedev",
        "ml", "data-science", "devops", "cloud", "docker", "kubernetes", "ffi", "unsafe", "generics",
        "iterators", "closures", "error-handling", "logging", "tracing", "benchmarking", "tooling",
        "cargo",
    ];
    for (i, name) in tags.iter().enumerate() {
        tag::ActiveModel {
            id: Set(i as i32 + 1),
            name: Set((*name).into()),
        }
        .insert(db)
        .await?;
    }

    // 45 posts → 2 pages at per_page 30; topics repeat so full-text search returns subsets.
    let topics = [
        "Rust", "Ownership", "Async", "Web", "Database", "Testing", "Performance", "Macros",
        "Traits", "Lifetimes",
    ];
    for i in 1..=45i32 {
        let topic = topics[(i as usize - 1) % topics.len()];
        post::ActiveModel {
            id: Set(i),
            title: Set(format!("{topic} deep dive #{i}")),
            body: Set(format!("Notes about {} — part {i}.", topic.to_lowercase())),
            views: Set((i * 37) % 500),
            published: Set(i % 4 != 0), // a mix of published / draft for the Yes/No badge
            // Spread publish times across ~45 hours from a fixed base (2023-11-14T22:13:20Z), and
            // leave drafts unpublished (None) — so the datetime column shows both values and blanks.
            published_at: Set((i % 4 != 0).then(|| 1_700_000_000i64 + i as i64 * 3600)),
            // Cycle through the allowed values, leaving every 7th row blank so the dropdown's "—" choice
            // has something to show (the column is nullable).
            status: Set(match i % 7 {
                0 => None,
                r => Some(["draft", "review", "published", "archived"][(r as usize - 1) % 4].to_string()),
            }),
            author_id: Set((i - 1) % authors.len() as i32 + 1),
        }
        .insert(db)
        .await?;

        let t1 = (i - 1) % tags.len() as i32 + 1;
        let t2 = i % tags.len() as i32 + 1;
        post_tag::ActiveModel {
            post_id: Set(i),
            tag_id: Set(t1),
        }
        .insert(db)
        .await?;
        if t2 != t1 {
            post_tag::ActiveModel {
                post_id: Set(i),
                tag_id: Set(t2),
            }
            .insert(db)
            .await?;
        }
    }

    for i in 1..=6i32 {
        user::ActiveModel {
            id: Set(i),
            username: Set(format!("user{i}")),
        }
        .insert(db)
        .await?;
        profile::ActiveModel {
            id: Set(i),
            user_id: Set(i),
            bio: Set(format!("Bio of user {i}")),
        }
        .insert(db)
        .await?;
    }
    Ok(())
}
