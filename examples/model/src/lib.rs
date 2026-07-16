//! Example domain model + a helper to spin up a seeded in-memory SQLite database.
//! The `autocrud` library knows nothing about any of this.

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
    ActiveModelTrait, ConnectionTrait, Database, DatabaseConnection, DbErr, EntityTrait, Schema,
    Set,
};

/// Connect to a fresh in-memory SQLite DB, create the schema from the entities, and seed data.
pub async fn setup() -> Result<DatabaseConnection, DbErr> {
    let db = Database::connect("sqlite::memory:").await?;
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
    let authors = [
        ("Ada Lovelace", "UK"),
        ("Bjarne Stroustrup", "DK"),
        ("Grace Hopper", "US"),
        ("Linus Torvalds", "FI"),
        ("Barbara Liskov", "US"),
        ("Alan Kay", "US"),
    ];
    for (i, (name, country)) in authors.iter().enumerate() {
        author::ActiveModel {
            id: Set(i as i32 + 1),
            name: Set((*name).into()),
            country: Set((*country).into()),
        }
        .insert(db)
        .await?;
    }

    let tags = [
        "rust", "systems", "beginner", "async", "web", "database", "testing", "performance",
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
