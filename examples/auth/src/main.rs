//! examples/auth — playground for `relativelylight`'s `auth` module (feature `auth`), used without
//! the `crud` feature to show `auth` stands on its own. See `docs/AUTH.md`.
//!
//! Current state: a public page and a "protected" page that is **not yet gated**. Gating (a login
//! page, a session cookie, and an `Authz` check) arrives with the `auth` implementation.

use axum::response::Html;
use axum::routing::get;
use axum::Router;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/", get(public))
        .route("/secret", get(secret));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await?;
    println!("auth playground on http://127.0.0.1:3001/");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn public() -> Html<&'static str> {
    Html(r#"<!doctype html><meta charset="utf-8"><title>Auth playground</title>
<h1>Public page</h1>
<p>relativelylight auth playground (see <code>docs/AUTH.md</code>).
Try <a href="/secret">/secret</a> — soon it will require a login.</p>"#)
}

// TODO(auth): gate this behind a session (redirect to the `auth` login page when anonymous).
async fn secret() -> Html<&'static str> {
    Html(r#"<!doctype html><meta charset="utf-8"><title>Protected</title>
<h1>Protected page</h1>
<p>Not gated yet — this is where the <code>auth</code> crate will require an authenticated user.</p>"#)
}
