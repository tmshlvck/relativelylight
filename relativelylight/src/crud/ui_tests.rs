//! Tests for the rendered UI — `Table`, `Form`, `Admin`.
//!
//! These drive a **hand-written `Accessor`** rather than a database: everything the UI decides, it
//! decides from the typed columns, so a mock entity pins the behaviour exactly and the suite stays
//! instant. (`list_tests` covers what only a real database can show, and `gate_tests` the negative
//! authorization cases.) What's covered here:
//!
//! - the render-time checks that turn a *silently broken screen* into an error naming the column: an
//!   unknown field, a read-only one, a create that omits a required column, an unsortable sort key, a
//!   filter on a column that doesn't exist, a widget that can't render its column;
//! - that each `Column` shape renders the right cell and the right form input, in the caller's
//!   timezone where that applies;
//! - **escaping**, on every path where a value reaches the page — the thing server-rendering makes
//!   this crate's problem, where `x-text` used to make it the browser's;
//! - the URL as state: `?edit=7` renders the dialog, `?entity=` picks one panel, headers link to the
//!   next sort, the pager carries the view;
//! - form decoding, including the cases a browser makes unavoidable (empty vs null, an unchecked
//!   checkbox, a blank write-only field) and a crafted body naming a column the form never rendered;
//! - the write path's outcomes: a redirect that lands on the row, and a rejection that comes back with
//!   the messages *and* the operator's input.

use super::ui::{esc, Admin, Form, Mode, Outcome, Table, ViewState};
use crate::authz::{Authz, Decision, Open, Operation};
use crate::crud::engine::{
    Accessor, Cardinality, Column, Engine, Error, FieldDisplay, ListQuery, LogicalType, Page,
    Result, RowItem, ValidationErrors,
};
use async_trait::async_trait;
use http::HeaderMap;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ---------- fixtures ----------

fn field(name: &str, required: bool, read_only: bool, default: Option<Value>) -> Column {
    Column::Field {
        name: name.into(),
        logical_type: LogicalType::Text,
        read_only,
        write_only: false,
        nullable: !required,
        required,
        options: Vec::new(),
        label: None,
        description: None,
        default,
        display: None,
        sortable: true,
    }
}

fn typed(name: &str, lt: LogicalType, nullable: bool) -> Column {
    Column::Field {
        name: name.into(),
        logical_type: lt,
        read_only: false,
        write_only: false,
        nullable,
        required: false,
        options: Vec::new(),
        label: None,
        description: None,
        default: None,
        display: None,
        sortable: true,
    }
}

fn with_display(name: &str, lt: LogicalType, options: Vec<String>, d: Option<FieldDisplay>) -> Column {
    Column::Field {
        name: name.into(),
        logical_type: lt,
        read_only: false,
        write_only: false,
        nullable: true,
        required: false,
        options,
        label: None,
        description: None,
        default: None,
        display: d,
        sortable: true,
    }
}

/// What a write reached the backend as — so a test can assert on the decoded body, and a gate test can
/// assert nothing arrived at all.
#[derive(Default)]
struct Log {
    writes: Mutex<Vec<(String, Value)>>,
}

impl Log {
    fn record(&self, what: &str, body: &Value) {
        self.writes.lock().unwrap().push((what.to_string(), body.clone()));
    }
    fn last(&self) -> (String, Value) {
        self.writes.lock().unwrap().last().cloned().expect("a write reached the backend")
    }
    fn count(&self) -> usize {
        self.writes.lock().unwrap().len()
    }
}

struct Mock {
    slug: String,
    cols: Vec<Column>,
    rows: Vec<Value>,
    /// A column name whose write is always refused, to exercise the `422` path.
    reject: Option<String>,
    log: Arc<Log>,
}

impl Mock {
    fn new(slug: &str, cols: Vec<Column>) -> Self {
        Self { slug: slug.into(), cols, rows: Vec::new(), reject: None, log: Arc::default() }
    }
    fn rows(mut self, rows: Vec<Value>) -> Self {
        self.rows = rows;
        self
    }
    fn rejecting(mut self, field: &str) -> Self {
        self.reject = Some(field.into());
        self
    }
}

#[async_trait]
impl Accessor for Mock {
    fn slug(&self) -> &str {
        &self.slug
    }
    fn pk(&self) -> String {
        "id".into()
    }
    fn columns(&self) -> Vec<Column> {
        self.cols.clone()
    }
    /// Honours `pk_in` and `per_page` — the two the UI leans on (an exact id lookup for a filter's
    /// label, and the cap that decides whether a relation can be listed at all). Search, filters
    /// and sort are a real backend's job and `list_tests` covers them there.
    async fn list(&self, q: &ListQuery, terse: bool) -> Result<Page> {
        let key = |r: &Value| match r.get("id") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        };
        let matching: Vec<&Value> = self
            .rows
            .iter()
            .filter(|r| q.pk_in.is_empty() || q.pk_in.contains(&key(r)))
            .collect();
        let per_page = if q.per_page == 0 { 30 } else { q.per_page };
        let data = matching
            .iter()
            .take(per_page as usize)
            .map(|r| {
                let id = r.get("id").cloned().unwrap_or(Value::Null);
                let label = crate::crud::engine::default_label(r);
                RowItem::new(id, label, (!terse).then(|| (*r).clone()))
            })
            .collect::<Vec<_>>();
        Ok(Page::new(matching.len() as u64, q.page.max(1), per_page, data))
    }
    async fn get(&self, pk: &str) -> Result<Option<Value>> {
        let key = |v: &Value| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        Ok(self.rows.iter().find(|r| r.get("id").map(key) == Some(pk.to_string())).cloned())
    }
    async fn create(&self, body: &Value) -> Result<Value> {
        if let Some(bad) = &self.reject {
            let mut errs = ValidationErrors::new();
            errs.field(bad, "not allowed");
            errs.general("the row as a whole is wrong");
            return Err(Error::Validation(errs));
        }
        self.log.record("create", body);
        let mut row = body.clone();
        row["id"] = json!(99);
        Ok(row)
    }
    async fn update(&self, pk: &str, body: &Value) -> Result<Option<Value>> {
        if let Some(bad) = &self.reject {
            let mut errs = ValidationErrors::new();
            errs.field(bad, "not allowed");
            return Err(Error::Validation(errs));
        }
        self.log.record("update", body);
        let mut row = body.clone();
        row["id"] = json!(pk);
        Ok(Some(row))
    }
    async fn delete(&self, pk: &str) -> Result<Option<Value>> {
        self.log.record("delete", &json!(pk));
        Ok(Some(json!({ "id": pk })))
    }
    async fn delete_many(&self, q: &ListQuery) -> Result<Vec<Value>> {
        self.log.record("delete_many", &json!({ "ids": q.pk_in, "eq": q.eq, "all": q.all }));
        // One row per id, so a caller reading `before_rows` sees what a real backend would return.
        Ok(q.pk_in.iter().map(|id| json!({ "id": id })).collect())
    }
}

/// The `post` entity used by most tests: one of every interesting shape.
fn post_columns() -> Vec<Column> {
    vec![
        field("id", false, true, None),                             // read-only PK
        field("title", true, false, None),                          // required, no default
        field("slug", true, false, Some(json!("x"))),               // required *with* a default
        field("body", false, false, None),                          // optional
        field("created_at", false, true, None),                     // read-only (hook-stamped)
        typed("views", LogicalType::Int, false),
        typed("published", LogicalType::Bool, false),
        with_display("published_at", LogicalType::Int, vec![], Some(FieldDisplay::DateTime)),
        Column::Field {
            name: "status".into(),
            logical_type: LogicalType::Enum,
            read_only: false,
            write_only: false,
            nullable: true,
            required: false,
            options: vec!["draft".into(), "published".into()],
            label: None,
            description: None,
            default: None,
            display: None,
            sortable: true,
        },
        Column::Field {
            name: "secret".into(),
            logical_type: LogicalType::Text,
            read_only: false,
            write_only: true,
            nullable: true,
            required: false,
            options: Vec::new(),
            label: None,
            description: None,
            default: None,
            display: None,
            sortable: false,
        },
        Column::Relation {
            name: "author".into(),
            target: "author".into(),
            cardinality: Cardinality::ToOne,
            fk_column: Some("author_id".into()),
            read_only: false,
            label: Some("Author".into()),
            description: None,
            sortable: true,
        },
        Column::Relation {
            name: "tag".into(),
            target: "tag".into(),
            cardinality: Cardinality::ToMany,
            fk_column: None,
            read_only: false,
            label: Some("Tags".into()),
            description: None,
            sortable: false,
        },
    ]
}

fn post_rows() -> Vec<Value> {
    vec![json!({
        "id": 7,
        "title": "First post",
        "slug": "first",
        "body": "hello",
        "created_at": "yesterday",
        "views": 12,
        "published": true,
        "published_at": 1_733_050_800i64,     // 2024-12-01 11:00 UTC
        "status": "draft",
        "author": { "id": 3, "label": "Ada" },
        "tag": [{ "id": 1, "label": "rust" }, { "id": 2, "label": "web" }],
    })]
}

/// A gate that always answers the same thing.
struct Always(Decision);

#[async_trait]
impl Authz for Always {
    async fn authorize(&self, _op: Operation, _headers: &HeaderMap) -> Decision {
        self.0
    }
}

/// A gate that allows reads and refuses writes — the `editor` case.
struct ReadOnlyGate;

#[async_trait]
impl Authz for ReadOnlyGate {
    async fn authorize(&self, op: Operation, _headers: &HeaderMap) -> Decision {
        if op.is_write() {
            Decision::Denied
        } else {
            Decision::Allow
        }
    }
}

/// An engine with `post` (rows and relations), plus the two relation targets it points at.
fn engine_with(gate: Arc<dyn Authz>) -> (Engine, Arc<Log>) {
    let post = Mock::new("post", post_columns()).rows(post_rows());
    let log = post.log.clone();
    let mut e = Engine::new();
    e.add(Arc::new(post), gate);
    e.add(
        Arc::new(
            Mock::new("author", vec![field("id", false, true, None), field("name", true, false, None)])
                .rows(vec![json!({"id": 3, "name": "Ada"}), json!({"id": 4, "name": "Grace"})]),
        ),
        Arc::new(Open),
    );
    e.add(
        Arc::new(
            Mock::new("tag", vec![field("id", false, true, None), field("name", true, false, None)])
                .rows(vec![json!({"id": 1, "name": "rust"}), json!({"id": 2, "name": "web"})]),
        ),
        Arc::new(Open),
    );
    // A second entity with an `author` relation, so a shared filter has somewhere to follow *to*.
    e.add(
        Arc::new(
            Mock::new(
                "note",
                vec![
                    field("id", false, true, None),
                    field("body", true, false, None),
                    Column::Relation {
                        name: "author".into(),
                        target: "author".into(),
                        cardinality: Cardinality::ToOne,
                        fk_column: Some("author_id".into()),
                        read_only: false,
                        label: Some("Author".into()),
                        description: None,
                        sortable: true,
                    },
                ],
            )
            .rows(vec![json!({"id": 1, "body": "a note", "author": {"id": 3, "label": "Ada"}})]),
        ),
        Arc::new(Open),
    );
    (e, log)
}

fn engine() -> (Engine, Arc<Log>) {
    engine_with(Arc::new(Open))
}

fn no_headers() -> HeaderMap {
    HeaderMap::new()
}

fn zone(name: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(http::header::COOKIE, format!("rl_tz={name}").parse().unwrap());
    h
}

fn list() -> ViewState {
    ViewState::default()
}

async fn render(table: &Table<'_>, state: &ViewState) -> String {
    table.render_for(&no_headers(), state).await.expect("renders")
}

// ---------- render-time checks: a broken screen is an error, naming the column ----------

#[tokio::test]
async fn a_misspelled_field_name_is_an_error_naming_the_known_columns() {
    let (e, _) = engine();
    let err = Form::new(&e, "post")
        .fields(["title", "ttile"])
        .render_for(&no_headers(), &list())
        .await
        .expect_err("a typo must not render");
    let msg = err.to_string();
    assert!(msg.contains("no column 'ttile'"), "{msg}");
    assert!(msg.contains("known columns:") && msg.contains("title"), "{msg}");
}

#[tokio::test]
async fn a_read_only_column_cannot_be_put_in_a_form() {
    let (e, _) = engine();
    let err = Form::new(&e, "post")
        .fields(["title", "created_at"])
        .render_for(&no_headers(), &list())
        .await
        .expect_err("read-only is not writable");
    assert!(err.to_string().contains("'created_at' is read-only"), "{err}");
}

#[tokio::test]
async fn creating_without_a_required_column_is_refused_before_it_can_fail() {
    let (e, _) = engine();
    let err = Form::new(&e, "post")
        .fields(["body"])
        .render_for(&no_headers(), &list())
        .await
        .expect_err("title and slug are required");
    let msg = err.to_string();
    assert!(msg.contains("title") && msg.contains("slug"), "{msg}");
    assert!(msg.contains("pre-fills the input"), "explains why a default doesn't excuse it: {msg}");
}

#[tokio::test]
async fn editing_may_omit_a_required_column_because_the_row_already_has_one() {
    let (e, _) = engine();
    Form::new(&e, "post")
        .edit("7")
        .fields(["body"])
        .render_for(&no_headers(), &list())
        .await
        .expect("an edit needs only what it shows");
}

#[tokio::test]
async fn a_widget_that_cannot_render_its_column_is_refused_by_name() {
    for (display, expected) in [
        (FieldDisplay::Radio, "there is nothing to list"),
        (FieldDisplay::Range { min: 0.0, max: 1.0, step: 0.1 }, "needs a numeric column"),
        (FieldDisplay::Textarea { rows: 2 }, "needs a text column"),
        (FieldDisplay::DateTime, "integer column"),
    ] {
        let mut e = Engine::new();
        let cols = vec![field("id", false, true, None), with_display("n", LogicalType::Uuid, vec![], Some(display))];
        e.add(Arc::new(Mock::new("thing", cols)), Arc::new(Open));
        let err = Table::new(&e, "thing")
            .render_for(&no_headers(), &list())
            .await
            .expect_err("a widget that can't fit must not render");
        let msg = err.to_string();
        assert!(msg.contains("field 'n'") && msg.contains(expected), "{msg}");
    }
}

#[tokio::test]
async fn a_table_refuses_a_default_sort_the_backend_would_reject() {
    let (e, _) = engine();
    let err = Table::new(&e, "post")
        .sort("nope")
        .render_for(&no_headers(), &list())
        .await
        .expect_err("unknown sort key");
    assert!(err.to_string().contains("cannot sort by 'nope'"), "{err}");

    let err = Table::new(&e, "post")
        .sort("tag") // a to-many has many labels per row, so there is no ordering to give
        .render_for(&no_headers(), &list())
        .await
        .expect_err("unsortable column");
    assert!(err.to_string().contains("'tag' is not sortable"), "{err}");
}

#[tokio::test]
async fn a_filter_on_a_column_that_does_not_exist_is_refused_but_a_shared_one_is_skipped() {
    let (e, _) = engine();
    let err = Table::new(&e, "post")
        .filter("zone")
        .render_for(&no_headers(), &list())
        .await
        .expect_err("a control that filtered nothing would look like it worked");
    assert!(err.to_string().contains("cannot filter by 'zone'"), "{err}");

    // An Admin-wide filter is offered to every table; the ones without the column skip it silently,
    // which is the whole point of the shape.
    let html = Admin::new(&e)
        .filter("author")
        .entity("post")
        .entity("tag")
        .render_for(&no_headers(), &ViewState::from_query("entity=tag"))
        .await
        .expect("tag has no author column, and that is fine");
    assert!(!html.contains("filter[author]"), "no control where there is no column");
}

#[tokio::test]
async fn an_admin_filter_no_listed_entity_has_is_an_error() {
    let (e, _) = engine();
    let err = Admin::new(&e)
        .filter("zone")
        .entity("post")
        .render_for(&no_headers(), &list())
        .await
        .expect_err("every table would drop it, so the panel would render no control at all");
    assert!(err.to_string().contains("no listed entity"), "{err}");
}

#[tokio::test]
async fn an_unregistered_entity_is_an_error() {
    let (e, _) = engine();
    assert!(Table::new(&e, "ghost").render_for(&no_headers(), &list()).await.is_err());
    assert!(Form::new(&e, "ghost").render_for(&no_headers(), &list()).await.is_err());
}

// ---------- cells: one `match` per column shape ----------

#[tokio::test]
async fn each_column_shape_renders_its_own_cell() {
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post"), &list()).await;
    assert!(html.contains("First post"), "a text cell is its value");
    assert!(html.contains(r#"<span class="badge text-bg-success">Yes</span>"#), "a bool is a badge");
    assert!(html.contains("Ada"), "a to-one relation shows the label the backend resolved");
    assert!(
        html.contains(r#"<span class="badge text-bg-secondary">rust</span>"#),
        "a to-many is badges: {html}"
    );
    assert!(html.contains("2024-12-01 11:00"), "an int-seconds datetime column is readable");
}

#[tokio::test]
async fn a_bool_cell_distinguishes_false_from_unset() {
    let cols = vec![field("id", false, true, None), typed("flag", LogicalType::Bool, true)];
    let mut e = Engine::new();
    e.add(
        Arc::new(Mock::new("thing", cols).rows(vec![
            json!({"id": 1, "flag": true}),
            json!({"id": 2, "flag": false}),
            json!({"id": 3, "flag": null}),
        ])),
        Arc::new(Open),
    );
    let html = render(&Table::new(&e, "thing"), &list()).await;
    assert!(html.contains(">Yes<") && html.contains(">No<"), "{html}");
    assert!(html.contains("—"), "null is neither yes nor no: {html}");
}

#[tokio::test]
async fn a_datetime_cell_and_input_follow_the_callers_zone() {
    let (e, _) = engine();
    let html = Table::new(&e, "post")
        .render_for(&zone("Asia/Tokyo"), &ViewState::from_query("edit=7"))
        .await
        .expect("renders");
    assert!(html.contains("2024-12-01 20:00"), "the cell is in the caller's zone: {html}");
    assert!(html.contains(r#"value="2024-12-01T20:00""#), "and so is the form input");
    assert!(html.contains("Times are Asia/Tokyo."), "the form says which zone it means");
}

#[tokio::test]
async fn a_format_closure_replaces_the_cell_and_escaping_is_its_job() {
    let (e, _) = engine();
    let table = Table::new(&e, "post").format("title", |v, row| {
        format!(r#"<a href="/post/{}">{}</a>"#, esc(&row["id"]), esc(v))
    });
    let html = render(&table, &list()).await;
    assert!(html.contains(r#"<a href="/post/7">First post</a>"#), "{html}");
}

// ---------- escaping: server-rendering makes this ours ----------

const NASTY: &str = "<script>alert(1)</script>";

#[tokio::test]
async fn nothing_that_reaches_the_page_can_carry_markup() {
    let mut cols = post_columns();
    // A label and an option set an app controls, and row data a user controls.
    cols.push(with_display("mood", LogicalType::Text, vec![NASTY.to_string()], None));
    let rows = vec![json!({
        "id": NASTY,
        "title": NASTY,
        "author": { "id": NASTY, "label": NASTY },
        "tag": [{ "id": 1, "label": NASTY }],
        "mood": NASTY,
    })];
    let mut e = Engine::new();
    e.add(Arc::new(Mock::new("post", cols).rows(rows)), Arc::new(Open));
    e.add(Arc::new(Mock::new("author", vec![field("id", false, true, None)]).rows(vec![json!({"id": NASTY})])), Arc::new(Open));
    e.add(Arc::new(Mock::new("tag", vec![field("id", false, true, None)]).rows(vec![])), Arc::new(Open));

    let table = Table::new(&e, "post")
        .title(NASTY)
        .description(NASTY)
        .filter("mood");
    for state in [
        ViewState::from_query(&format!("q={NASTY}&filter[mood]={NASTY}")),
        ViewState::from_query("edit=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ] {
        let html = table.render_for(&no_headers(), &state).await.expect("renders");
        assert!(
            !html.contains("<script>"),
            "unescaped markup reached the page from {:?}:\n{html}",
            state.mode
        );
        assert!(
            html.contains("&#60;script") || html.contains("&lt;script"),
            "…and it should still be *shown*, escaped: {html}"
        );
    }
}

#[tokio::test]
async fn a_row_error_message_is_escaped_too() {
    // Validation messages can quote user input, so they are on the same footing as a cell.
    let post = Mock::new("post", post_columns()).rejecting("title");
    let mut e = Engine::new();
    e.add(Arc::new(post), Arc::new(Open));
    e.add(Arc::new(Mock::new("author", vec![field("id", false, true, None)]).rows(vec![])), Arc::new(Open));
    e.add(Arc::new(Mock::new("tag", vec![field("id", false, true, None)]).rows(vec![])), Arc::new(Open));
    let table = Table::new(&e, "post");
    let body = format!("_op=create&title={NASTY}&slug=s");
    let Outcome::Invalid(state) = table.submit(&no_headers(), IP, body.as_bytes(), &list()).await.unwrap()
    else {
        panic!("the mock rejects every write");
    };
    let html = table.render_for(&no_headers(), &state).await.expect("re-renders");
    assert!(!html.contains("<script>"), "{html}");
}

// ---------- the URL is the state ----------

#[tokio::test]
async fn the_dialog_is_opened_by_the_url_and_carries_the_rows_values() {
    let (e, _) = engine();
    let table = Table::new(&e, "post");

    let plain = render(&table, &list()).await;
    assert!(!plain.contains("<dialog"), "no dialog unless the URL asks for one");

    let editing = render(&table, &ViewState::from_query("edit=7")).await;
    assert!(editing.contains("<dialog open"), "?edit=7 renders it server-side");
    assert!(editing.contains(r#"value="First post""#), "with the row's values in the inputs");
    assert!(editing.contains(r#"name="_op" value="update""#));
    assert!(editing.contains(r#"name="_id" value="7""#));

    let creating = render(&table, &ViewState::from_query("new=1")).await;
    assert!(creating.contains(r#"name="_op" value="create""#));
    assert!(creating.contains(r#"value="x""#), "a column default pre-fills the input");
    assert!(!creating.contains(r#"value="First post""#), "and no row's values leak into a create");
}

#[tokio::test]
async fn a_sortable_header_links_to_the_next_sort_and_says_which_way_it_is_going() {
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post"), &ViewState::from_query("sort=title")).await;
    assert!(html.contains(r#"aria-sort="ascending""#), "{html}");
    assert!(html.contains("▲"), "the mark a sighted user reads");
    assert!(html.contains("sort=title%3Adesc"), "clicking again reverses it");
    assert!(html.contains("title=\"Add as a secondary sort key\""), "multi-key is discoverable");
    // A to-many is not sortable, so its header is text, not a link.
    let head = html.split("Tags").next().unwrap();
    assert!(!head.ends_with("<a "), "{html}");
}

#[tokio::test]
async fn the_pager_carries_the_view_and_disappears_when_there_is_one_page() {
    let rows: Vec<Value> = (1..=95).map(|i| json!({"id": i, "title": format!("row {i}")})).collect();
    let cols = vec![field("id", false, true, None), field("title", true, false, None)];
    let mut e = Engine::new();
    e.add(Arc::new(Mock::new("thing", cols).rows(rows)), Arc::new(Open));

    let html = Table::new(&e, "thing")
        .per_page(10)
        .render_for(&no_headers(), &ViewState::from_query("q=row&page=3"))
        .await
        .unwrap();
    assert!(html.contains("Page 3 / 10") && html.contains("Total: 95"), "{html}");
    let link = html.split(">4</a>").next().unwrap().rsplit("href=\"").next().unwrap();
    assert!(link.contains("q=row") && link.contains("page=4"), "a page link keeps the search: {link}");
    let jump = html.split("»</a>").next().unwrap().rsplit("href=\"").next().unwrap();
    assert!(jump.contains("page=4"), "» steps by a tenth of the table: {jump}");

    let one_page = Table::new(&e, "thing").per_page(100).render_for(&no_headers(), &list()).await.unwrap();
    assert!(!one_page.contains("<ul class=\"pagination"), "nothing to page through");
    assert!(one_page.contains("Total: 95"), "but the count is still worth having");
}

#[tokio::test]
async fn a_filtered_view_says_so_and_offers_a_way_out() {
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post").filter("status"), &ViewState::from_query("filter[status]=draft")).await;
    assert!(html.contains(r#"<option value="*">status: all</option>"#), "a way back to everything");
    assert!(html.contains("<strong>draft</strong>"), "the chip that stops 'where did my rows go': {html}");
    assert!(html.contains("Clear status filter"), "and a way to remove it");
    assert!(html.contains(r#"value="draft" selected"#), "the control shows the active value");
}

#[tokio::test]
async fn choosing_all_clears_the_filter_rather_than_asking_for_the_orphans() {
    // `filter[author]=` means "rows with no author", so the toolbar's "all" cannot submit an empty
    // value: it did, and choosing it filtered a table down to nothing.
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post").filter("author"), &list()).await;
    assert!(html.contains(r#"<option value="*">Author: all</option>"#), "{html}");

    let all = ViewState::from_query("filter[author]=*");
    assert!(all.filters.is_empty(), "`*` is no filter at all");
    assert!(all.to_list_query(30).eq.is_empty(), "so nothing reaches the query");
    assert!(!all.to_query().contains("filter"), "and it doesn't linger in the URL");

    // The documented meaning of an empty value is untouched.
    let orphans = ViewState::from_query("filter[author]=");
    assert_eq!(orphans.to_list_query(30).eq, vec![("author".to_string(), String::new())]);
}

#[tokio::test]
async fn a_filter_whose_target_is_too_large_says_so_instead_of_listing_a_fifth_of_it() {
    // A `<select>` capped at `picker_threshold` hides most of the values *and* misreports the one
    // in force: with nothing selected the browser shows the first option, so the control would
    // claim a filter the table isn't using.
    let rows: Vec<Value> = (1..=50).map(|i| json!({"id": i, "name": format!("author {i}")})).collect();
    let mut e = Engine::new();
    e.add(Arc::new(Mock::new("post", post_columns()).rows(post_rows())), Arc::new(Open));
    e.add(
        Arc::new(
            Mock::new("author", vec![field("id", false, true, None), field("name", true, false, None)])
                .rows(rows),
        ),
        Arc::new(Open),
    );
    e.add(Arc::new(Mock::new("tag", vec![field("id", false, true, None)]).rows(vec![])), Arc::new(Open));

    let table = Table::new(&e, "post").filter("author").picker_threshold(20);
    let html = table
        .render_for(&no_headers(), &ViewState::from_query("filter[author]=42"))
        .await
        .unwrap();
    assert!(!html.contains(r#"<select class="form-select form-select-sm w-auto" name="filter[author]""#),
            "no truncated menu for the filter: {html}");
    assert!(html.contains(r#"value="42""#), "the filter in force is what the control shows");
    assert!(html.contains("any of 50"), "and it says how many there are: {html}");
    assert!(html.contains("<strong>author 42</strong>"), "the chip resolves its label: {html}");

    // Under the threshold it is a menu again, with the right option marked.
    let small = Table::new(&e, "post").filter("author").picker_threshold(100);
    let html = small
        .render_for(&no_headers(), &ViewState::from_query("filter[author]=42"))
        .await
        .unwrap();
    assert!(html.contains(r#"<option value="42" selected>author 42</option>"#), "{html}");
}

#[tokio::test]
async fn a_pinned_filter_is_shown_but_not_offered_and_cannot_be_cleared() {
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post").fixed_filter("status", "draft"), &list()).await;
    assert!(html.contains("<strong>draft</strong>"), "{html}");
    assert!(!html.contains("Clear status filter"), "it isn't this table's to clear");
    assert!(!html.contains(r#"name="filter[status]""#), "and there is no control for it");
}

// ---------- Admin ----------

#[tokio::test]
async fn an_admin_can_address_its_entities_by_path() {
    let (e, _) = engine();
    let admin = Admin::new(&e).base("/admin").filter("author").entity("post").entity("note").entity("tag");

    // The app routes `/admin/{entity}` and tells the panel which one from the path.
    let mut state = ViewState::from_query("filter[author]=3&page=2");
    state.entity = Some("post".into());
    let html = admin.render_for(&no_headers(), &state).await.unwrap();

    assert!(html.contains(r#"href="/admin/tag""#), "a path, not a query: {html}");
    assert!(
        html.contains(r#"href="/admin/note?filter%5Bauthor%5D=3""#),
        "and what travels still travels: {html}"
    );
    assert!(html.contains(r#"class="nav-link py-1 active" href="/admin/post"#), "{html}");
    assert!(!html.contains("entity=tag"), "no query-addressed links left: {html}");

    // Everything *inside* the table stays relative, so it resolves against /admin/post — the panel
    // never needs to know where it is mounted.
    let panel = html.split("<main").nth(1).expect("the panel");
    assert!(!panel.contains("/admin/"), "the table knows nothing about the mount: {panel}");
    assert!(panel.contains(r#"href="?"#) || panel.contains(r#"href="?filter"#), "{panel}");
    assert!(panel.contains("edit=7"), "and its row links still work: {panel}");

    // Without `base` it is one page addressed by query, as before.
    let one_page = Admin::new(&e).entity("post").entity("tag");
    let html = one_page.render_for(&no_headers(), &ViewState::default()).await.unwrap();
    assert!(html.contains(r#"href="?entity=tag""#), "{html}");
}

#[tokio::test]
async fn an_admin_renders_exactly_one_panel() {
    let (e, _) = engine();
    let admin = Admin::new(&e).title("Admin").group("Content").entity("post").entity("tag").separator().link("Out", "/logout");
    let html = admin.render_for(&no_headers(), &ViewState::from_query("entity=tag")).await.unwrap();
    assert_eq!(html.matches("<table").count(), 1, "one table, not one per registered entity");
    assert!(html.contains("entity=post"), "the others are links");
    assert!(html.contains(r#"class="nav-link py-1 active" href="?entity=tag""#), "{html}");
    assert!(html.contains("/logout"), "custom links render");
    assert!(!html.contains("First post"), "the post rows are not in the response at all");
}

#[tokio::test]
async fn a_shared_filter_follows_the_operator_only_where_it_means_something() {
    let (e, _) = engine();
    let admin = Admin::new(&e).filter("author").entity("post").entity("note").entity("tag");
    let html = admin
        .render_for(&no_headers(), &ViewState::from_query("entity=post&filter[author]=3"))
        .await
        .unwrap();
    let link_to = |slug: &str, html: &str| {
        html.split(&format!(">{slug}</a>")).next().unwrap().rsplit("href=\"").next().unwrap().to_string()
    };

    // `note` has an author, so the operator keeps their zone when they go there.
    let note = link_to("note", &html);
    assert!(note.contains("entity=note") && note.contains("filter%5Bauthor%5D=3"), "{note}");

    // `tag` has none. A link that carried it would narrow nothing and name a column that isn't
    // there — which is what made the other tables' endpoints fail.
    let tag = link_to("tag", &html);
    assert!(tag.contains("entity=tag") && !tag.contains("author"), "{tag}");

    assert!(html.contains("<strong>Ada</strong>"), "and the chip names it, not its id: {html}");
    assert!(!html.contains("Clear Author filter"), "a shared filter is cleared where it was set");

    // …and landing on `tag` *with* the filter still in the URL is harmless: it is ignored, not
    // passed to a backend that would refuse the whole listing.
    let on_tag = admin
        .render_for(&no_headers(), &ViewState::from_query("entity=tag&filter[author]=3"))
        .await
        .expect("a filter this entity can't honour must not break its panel");
    assert!(on_tag.contains("rust"), "the rows are there: {on_tag}");
}

// ---------- gating ----------

#[tokio::test]
async fn a_form_refuses_rather_than_rendering_something_that_cannot_submit() {
    for (decision, expect) in
        [(Decision::NeedsLogin, "unauthorized"), (Decision::Denied, "forbidden")]
    {
        let (e, _) = engine_with(Arc::new(Always(decision)));
        let err = Form::new(&e, "post")
            .render_for(&no_headers(), &list())
            .await
            .expect_err("a form nobody may submit is not a form");
        assert_eq!(err.to_string(), expect);
    }
}

#[tokio::test]
async fn an_edit_form_is_gated_on_update_not_create() {
    struct CreateOnly;
    #[async_trait]
    impl Authz for CreateOnly {
        async fn authorize(&self, op: Operation, _h: &HeaderMap) -> Decision {
            match op {
                Operation::Update => Decision::Denied,
                _ => Decision::Allow,
            }
        }
    }
    let (e, _) = engine_with(Arc::new(CreateOnly));
    Form::new(&e, "post").render_for(&no_headers(), &list()).await.expect("create is allowed");
    let err = Form::new(&e, "post").edit("7").render_for(&no_headers(), &list()).await.unwrap_err();
    assert_eq!(err.to_string(), "forbidden", "an edit asks about Update");
}

#[tokio::test]
async fn a_reader_gets_a_table_with_no_write_controls_at_all() {
    let (e, _) = engine_with(Arc::new(ReadOnlyGate));
    let html = render(&Table::new(&e, "post"), &ViewState::from_query("edit=7")).await;
    for control in ["+ New", "Delete", "Edit", "<dialog", "_csrf", "name=\"ids\""] {
        assert!(!html.contains(control), "a reader must not be offered '{control}':\n{html}");
    }
    assert!(html.contains("First post"), "but they can still read");

    // `read_only(true)` does the same for everyone, gate or no gate.
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post").read_only(true), &list()).await;
    assert!(!html.contains("+ New"), "{html}");
}

// ---------- decoding a posted form ----------

/// Submit a body and return what the backend actually received.
async fn decoded(body: &str) -> Value {
    let (e, log) = engine();
    let table = Table::new(&e, "post");
    match table.submit(&no_headers(), IP, body.as_bytes(), &list()).await.expect("accepted") {
        Outcome::Done(_) => log.last().1,
        Outcome::Invalid(_) => panic!("the mock accepts every write"),
    }
}

#[tokio::test]
async fn empty_means_null_or_nothing_depending_on_the_column() {
    let body = decoded("_op=create&title=t&slug=s&body=&views=&published_at=&status=").await;
    assert_eq!(body["body"], Value::Null, "a nullable text column takes null");
    assert_eq!(body["status"], Value::Null, "so does a nullable enum");
    assert!(
        !body.as_object().unwrap().contains_key("views"),
        "an empty NOT NULL number is left to the column's default, not sent as zero: {body}"
    );
    assert_eq!(body["published_at"], Value::Null, "a nullable datetime clears to null");
    assert_eq!(body["title"], json!("t"), "and a value is a value");
}

#[tokio::test]
async fn an_unchecked_checkbox_is_false_not_missing() {
    let on = decoded("_op=create&title=t&slug=s&published=true").await;
    assert_eq!(on["published"], json!(true));
    let off = decoded("_op=create&title=t&slug=s").await;
    assert_eq!(off["published"], json!(false), "a browser posts nothing for an unchecked box");
}

#[tokio::test]
async fn a_blank_write_only_field_keeps_the_stored_value() {
    let blank = decoded("_op=update&_id=7&title=t&slug=s&secret=").await;
    assert!(!blank.as_object().unwrap().contains_key("secret"), "blank means keep: {blank}");
    let typed = decoded("_op=update&_id=7&title=t&slug=s&secret=hunter2").await;
    assert_eq!(typed["secret"], json!("hunter2"));
}

#[tokio::test]
async fn relations_decode_to_ids() {
    let body = decoded("_op=create&title=t&slug=s&author=3&tag=1&tag=2").await;
    assert_eq!(body["author"], json!(3), "a to-one is one id");
    assert_eq!(body["tag"], json!([1, 2]), "a to-many collects every posted value");
    let cleared = decoded("_op=create&title=t&slug=s&author=").await;
    assert_eq!(cleared["author"], Value::Null, "and blank clears it");
    assert_eq!(cleared["tag"], json!([]), "an empty multi-select clears the set");
}

#[tokio::test]
async fn a_datetime_input_is_read_in_the_callers_zone() {
    let (e, log) = engine();
    let table = Table::new(&e, "post");
    let body = "_op=create&title=t&slug=s&published_at=2024-12-01T12:00";
    table.submit(&zone("Europe/Prague"), IP, body.as_bytes(), &list()).await.unwrap();
    assert_eq!(log.last().1["published_at"], json!(1_733_050_800i64), "12:00 Prague is 11:00 UTC");
}

#[tokio::test]
async fn a_crafted_body_cannot_reach_a_column_the_form_never_rendered() {
    let (e, log) = engine();
    // This form shows two fields; the POST claims six.
    let table = Table::new(&e, "post").fields(["title", "slug"]);
    let body = "_op=create&title=t&slug=s&body=sneaky&views=999&created_at=1999&secret=x&author=4";
    table.submit(&no_headers(), IP, body.as_bytes(), &list()).await.unwrap();
    let got = log.last().1;
    let keys: Vec<&String> = got.as_object().unwrap().keys().collect();
    assert_eq!(keys, vec!["slug", "title"], "only the rendered fields are written: {got}");
}

// ---------- the write path ----------

#[tokio::test]
async fn a_save_lands_back_on_the_row_it_changed() {
    let (e, _) = engine();
    let table = Table::new(&e, "post");
    let state = ViewState::from_query("page=2&sort=title&edit=7");
    let outcome = table
        .submit(&no_headers(), IP, b"_op=update&_id=7&title=t&slug=s", &state)
        .await
        .unwrap();
    let Outcome::Done(to) = outcome else { panic!("accepted") };
    assert!(to.starts_with('?'), "relative, so the library never learns the page's path: {to}");
    assert!(to.contains("page=2") && to.contains("sort=title"), "the view comes back: {to}");
    assert!(!to.contains("edit="), "but not the dialog");
    assert!(to.ends_with("#row-7"), "and the browser lands on the row: {to}");
}

#[tokio::test]
async fn a_rejected_save_comes_back_with_the_messages_and_the_typed_values() {
    let post = Mock::new("post", post_columns()).rejecting("title");
    let mut e = Engine::new();
    e.add(Arc::new(post), Arc::new(Open));
    for target in ["author", "tag"] {
        e.add(Arc::new(Mock::new(target, vec![field("id", false, true, None)]).rows(vec![])), Arc::new(Open));
    }
    let table = Table::new(&e, "post");
    let body = "_op=create&title=Kept&slug=s&body=also+kept";
    let Outcome::Invalid(state) = table.submit(&no_headers(), IP, body.as_bytes(), &list()).await.unwrap()
    else {
        panic!("validation refused this write");
    };
    assert_eq!(state.mode, Mode::New, "the dialog reopens where it was");
    let html = table.render_for(&no_headers(), &state).await.unwrap();
    assert!(html.contains("<dialog open"), "{html}");
    assert!(html.contains("not allowed"), "the field message is beside its field");
    assert!(html.contains("the row as a whole is wrong"), "the row message is in the banner");
    assert!(html.contains(r#"value="Kept""#), "and the input the operator typed is still there");
    assert!(html.contains("also kept"));
}

#[tokio::test]
async fn one_row_deletes_by_its_own_button() {
    let (e, log) = engine();
    let table = Table::new(&e, "post");
    table.submit(&no_headers(), IP, b"_del=7", &list()).await.unwrap();
    assert_eq!(log.last(), ("delete".into(), json!("7")));
}

/// One observed `WriteEvent`, reduced to the parts the delete contract is about.
#[derive(Clone)]
struct Observed {
    op: Operation,
    key: Option<String>,
    rows: Vec<Value>,
}

/// Records every `WriteEvent` a test provokes, so the delete contract can be asserted.
#[derive(Default)]
struct Seen(std::sync::Mutex<Vec<Observed>>);

#[async_trait]
impl crate::observe::WriteObserver for Seen {
    async fn on_write(&self, ev: &crate::observe::WriteEvent<'_>) {
        self.0.lock().unwrap().push(Observed {
            op: ev.op,
            key: ev.key.clone(),
            rows: ev.before_rows.to_vec(),
        });
    }
}

/// **A delete tells the observer what it removed — all three of them, in one shape.**
///
/// Before `before_rows` existed, a bulk delete handed the observer `before: None` and `key: None`:
/// "something was deleted from `post`", and nothing more. An app with derived state — a search index
/// to evict, a cache to drop, a parent row to re-render — could not act on that, because by the time
/// it was called the rows were gone. The only workaround was for the app to read the rows itself
/// before handing the body over, duplicating this crate's query construction outside the transaction
/// that does the delete.
#[tokio::test]
async fn every_delete_hands_the_observer_the_rows_it_removed() {
    let seen = Arc::new(Seen::default());
    let (mut e, _log) = engine();
    e.set_observer(seen.clone());
    let table = Table::new(&e, "post");

    table.submit(&no_headers(), IP, b"_del=7", &list()).await.unwrap();
    table.submit(&no_headers(), IP, b"_op=delete_selected&ids=1&ids=2", &list()).await.unwrap();

    let events = seen.0.lock().unwrap().clone();
    assert_eq!(events.len(), 2);

    assert_eq!(events[0].op, Operation::Delete);
    assert_eq!(events[0].key.as_deref(), Some("7"), "a single delete still names its row");
    assert_eq!(events[0].rows.len(), 1, "and carries it in before_rows too, so one field serves both");

    assert_eq!(events[1].op, Operation::Delete);
    assert_eq!(events[1].key, None, "a bulk delete names no single row — hence before_rows");
    assert_eq!(events[1].rows.len(), 2, "one entry per row actually removed");

    // A create is not a delete, and must not look like one.
    table.submit(&no_headers(), IP, b"_op=create&title=x", &list()).await.unwrap();
    let last = seen.0.lock().unwrap().last().unwrap().clone();
    assert_eq!(last.op, Operation::Create);
    assert!(last.rows.is_empty(), "before_rows is empty for anything that is not a delete");
}

#[tokio::test]
async fn bulk_delete_never_acts_on_more_than_the_view_shows() {
    let (e, log) = engine();
    let table = Table::new(&e, "post").filter("status");
    let state = ViewState::from_query("filter[status]=draft");

    table
        .submit(&no_headers(), IP, b"_op=delete_selected&ids=1&ids=2", &state)
        .await
        .unwrap();
    let selected = log.last().1;
    assert_eq!(selected["ids"], json!(["1", "2"]), "only what was ticked");
    assert_eq!(selected["all"], json!(false), "and no permission to wipe the table");

    table.submit(&no_headers(), IP, b"_op=delete_all", &state).await.unwrap();
    let all = log.last().1;
    assert_eq!(all["eq"], json!([["status", "draft"]]), "'delete all' means all *matching*");
    assert_eq!(all["all"], json!(true));

    // Nothing ticked: don't fall through to deleting everything.
    let before = log.count();
    table.submit(&no_headers(), IP, b"_op=delete_selected", &state).await.unwrap();
    assert_eq!(log.count(), before, "an empty selection deletes nothing");
}

#[tokio::test]
async fn a_delete_reports_what_it_removed_and_an_edit_does_not() {
    let (e, _) = engine();
    let table = Table::new(&e, "post");

    // Deletes report: the rows are gone, so the count is the only feedback there is.
    let Outcome::Done(one) = table.submit(&no_headers(), IP, b"_del=7", &list()).await.unwrap()
    else {
        panic!("accepted")
    };
    assert!(one.contains("done=deleted:1"), "{one}");
    let Outcome::Done(many) = table
        .submit(&no_headers(), IP, b"_op=delete_selected&ids=1&ids=2", &list())
        .await
        .unwrap()
    else {
        panic!("accepted")
    };
    assert!(many.contains("done=deleted:2"), "{many}");

    // An edit doesn't: the redirect already lands on the row it changed.
    let Outcome::Done(edit) = table
        .submit(&no_headers(), IP, b"_op=update&_id=7&title=t&slug=s", &list())
        .await
        .unwrap()
    else {
        panic!("accepted")
    };
    assert!(!edit.contains("done="), "no alert for a one-row save: {edit}");
    assert!(edit.ends_with("#row-7"));

    // The alert renders above the table, once, with a way to dismiss it.
    let html = render(&table, &ViewState::from_query("done=deleted:17")).await;
    assert!(html.contains("17 records deleted."), "{html}");
    assert!(html.contains(r#"class="alert alert-success"#), "{html}");
    let after = render(&table, &ViewState::default()).await;
    assert!(!after.contains("records deleted"), "and not on the next page view");
}

#[tokio::test]
async fn a_message_about_a_column_the_form_hides_still_reaches_the_operator() {
    // Otherwise it is a refused form with nothing marked and no stated reason.
    let post = Mock::new("post", post_columns()).rejecting("views"); // not in `fields` below
    let mut e = Engine::new();
    e.add(Arc::new(post), Arc::new(Open));
    for target in ["author", "tag"] {
        e.add(Arc::new(Mock::new(target, vec![field("id", false, true, None)]).rows(vec![])), Arc::new(Open));
    }
    let table = Table::new(&e, "post").fields(["title", "slug"]);
    let Outcome::Invalid(state) = table
        .submit(&no_headers(), IP, b"_op=create&title=t&slug=s", &list())
        .await
        .unwrap()
    else {
        panic!("refused")
    };
    let html = table.render_for(&no_headers(), &state).await.unwrap();
    assert!(html.contains("views: not allowed"), "promoted to the banner: {html}");
    assert!(html.contains("alert alert-danger"), "{html}");
}

#[tokio::test]
async fn an_unknown_operation_is_a_bad_request_not_a_guess() {
    let (e, log) = engine();
    let err = Table::new(&e, "post")
        .submit(&no_headers(), IP, b"_op=drop_database", &list())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unknown form operation"), "{err}");
    assert_eq!(log.count(), 0);
}

#[tokio::test]
async fn an_admin_refuses_a_write_to_an_entity_it_does_not_list() {
    let (e, log) = engine();
    let admin = Admin::new(&e).entity("tag"); // `post` is registered, but not listed here
    let err = admin
        .submit(&no_headers(), IP, b"_op=create&_entity=post&title=t&slug=s", &list())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NotFound), "{err}");
    assert_eq!(log.count(), 0, "and it never reached the backend");
}

#[tokio::test]
async fn a_standalone_form_redirects_where_it_was_told_to() {
    let (e, _) = engine();
    let form = Form::new(&e, "post")
        .fields(["title", "slug"])
        .redirect("/post/{id}/edit");
    let Outcome::Done(to) = form
        .submit(&no_headers(), IP, b"_op=create&title=t&slug=s", &list())
        .await
        .unwrap()
    else {
        panic!("accepted")
    };
    assert_eq!(to, "/post/99/edit", "with the new row's id filled in");

    // Without a redirect it comes back to itself and says so.
    let plain = Form::new(&e, "post").fields(["title", "slug"]);
    let Outcome::Done(to) = plain.submit(&no_headers(), IP, b"_op=create&title=t&slug=s", &list()).await.unwrap()
    else {
        panic!("accepted")
    };
    assert_eq!(to, "?saved=1");
    let html = plain.render_for(&no_headers(), &ViewState::from_query("saved=1")).await.unwrap();
    assert!(html.contains("Saved."), "{html}");
}

// ---------- the read-only row ----------

#[tokio::test]
async fn a_row_can_be_read_whole_including_what_no_form_shows() {
    let (e, _) = engine();
    let table = Table::new(&e, "post");
    let html = render(&table, &ViewState::from_query("show=7")).await;

    let dialog = html.split("<dialog").nth(1).expect("the dialog").split("</dialog>").next().unwrap();
    assert!(dialog.contains("<dl class=\"row mb-0\">"), "a definition list, not a form: {dialog}");
    assert!(!dialog.contains("<input") && !dialog.contains("<form"), "nothing editable: {dialog}");

    // Columns a form never renders: the generated id, and a read-only hook-stamped column.
    assert!(dialog.contains(">id</dt>") && dialog.contains("7</dd>"), "{dialog}");
    assert!(dialog.contains("created_at") && dialog.contains("yesterday"), "{dialog}");
    // …rendered by the same code as the cells: labels, badges and the caller's timezone.
    assert!(dialog.contains("Ada"), "a relation shows its label");
    assert!(dialog.contains(r#"<span class="badge text-bg-secondary">rust</span>"#), "to-many badges");
    assert!(dialog.contains("badge text-bg-success"), "a bool shows its badge");
    assert!(dialog.contains("2024-12-01 11:00"), "a datetime is formatted");
}

#[tokio::test]
async fn the_detail_view_is_a_read_so_a_reader_gets_it_without_the_edit_button() {
    let (e, _) = engine_with(Arc::new(ReadOnlyGate));
    let table = Table::new(&e, "post");

    let list = render(&table, &list()).await;
    assert!(list.contains(">View</a>"), "a reader is offered the one action they may take: {list}");
    assert!(!list.contains(">Edit</a>"), "{list}");

    let shown = render(&table, &ViewState::from_query("show=7")).await;
    assert!(shown.contains("<dialog open"), "and the dialog opens for them: {shown}");
    assert!(!shown.contains(">Edit</a>"), "with no button they would be refused: {shown}");

    // A writer gets the button, pointing at the same row's editor.
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post"), &ViewState::from_query("show=7")).await;
    assert!(html.contains("edit=7"), "{html}");
}

#[tokio::test]
async fn a_table_can_decline_the_detail_view() {
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post").detail(false).read_only(true), &list()).await;
    assert!(!html.contains(">View</a>"), "{html}");
    assert!(!html.contains("<th class=\"text-end\">Actions</th>"), "and loses the column: {html}");
    assert!(html.contains("First post"), "but still shows its rows");
}

// ---------- how many rows a page shows ----------

#[tokio::test]
async fn the_toolbar_offers_page_sizes_and_marks_the_one_in_force() {
    let rows: Vec<Value> = (1..=500).map(|i| json!({"id": i, "title": format!("row {i}")})).collect();
    let cols = vec![field("id", false, true, None), field("title", true, false, None)];
    let mut e = Engine::new();
    e.add(Arc::new(Mock::new("thing", cols).rows(rows)), Arc::new(Open));

    // Links beside the pager, where a page size belongs — no form, no script, and the size in
    // force is text rather than a link to where you already are.
    let table = Table::new(&e, "thing").per_page(30);
    let html = table.render_for(&no_headers(), &ViewState::from_query("per_page=100")).await.unwrap();
    assert!(html.contains("<strong>100</strong>"), "the size in force is marked: {html}");
    assert!(html.contains("per_page=30"), "the others are links: {html}");
    assert!(html.contains("Page 1 / 5"), "and it is the size actually used: {html}");
    assert!(html.contains("Total: 500"), "the count shows even on one page");

    // Changing the size starts at the first page — page 9 of a 250-row listing may not exist.
    let deep = table.render_for(&no_headers(), &ViewState::from_query("per_page=10&page=9")).await.unwrap();
    let link = deep.split(">250</a>").next().unwrap().rsplit("href=\"").next().unwrap();
    assert!(link.contains("per_page=250") && !link.contains("page=9"), "{link}");

    // A configured size that isn't among the choices is still offered, so the size in force can
    // always be seen.
    let odd = Table::new(&e, "thing").per_page(42);
    let html = odd.render_for(&no_headers(), &list()).await.unwrap();
    assert!(html.contains("<strong>42</strong>"), "{html}");

    // …and a table can decline them entirely.
    let none = Table::new(&e, "thing").per_page_choices([]);
    let html = none.render_for(&no_headers(), &list()).await.unwrap();
    assert!(!html.contains("per_page="), "no sizes offered: {html}");
}

#[tokio::test]
async fn a_page_size_from_the_url_is_clamped() {
    // `?per_page=` is user input: unclamped it is a cheap way to make the server read a whole table
    // into memory and render it.
    let rows: Vec<Value> = (1..=500).map(|i| json!({"id": i, "title": format!("row {i}")})).collect();
    let cols = vec![field("id", false, true, None), field("title", true, false, None)];
    let mut e = Engine::new();
    e.add(Arc::new(Mock::new("thing", cols).rows(rows)), Arc::new(Open));

    let greedy = ViewState::from_query("per_page=100000000");
    let table = Table::new(&e, "thing").per_page_max(50);
    let html = table.render_for(&no_headers(), &greedy).await.unwrap();
    assert!(html.contains("Page 1 / 10"), "500 rows at the capped 50: {html}");
    assert!(!html.contains("100000000"), "and the greedy size is not offered back: {html}");
    assert!(html.contains("<strong>50</strong>"), "the cap is what's marked in force: {html}");

    // The default cap is 500 — a page no honest console asks past, and one whose relation columns
    // don't turn into thousands of queries (see `DEFAULT_PER_PAGE_MAX`).
    assert_eq!(Table::DEFAULT_PER_PAGE_MAX, 500);
    let defaulted = Table::new(&e, "thing").render_for(&no_headers(), &greedy).await.unwrap();
    assert!(!defaulted.contains("100000000"), "the URL's number is not echoed back: {defaulted}");

    // A bulk delete acts on the view, so it is bounded by the same clamp rather than the URL.
    let (e2, log) = engine();
    Table::new(&e2, "post")
        .per_page_max(5)
        .submit(&no_headers(), IP, b"_op=delete_all", &greedy)
        .await
        .unwrap();
    assert_eq!(log.last().1["all"], json!(true));
}

// ---------- choosing and marking what the table shows ----------

#[tokio::test]
async fn columns_narrows_and_orders_the_table_without_touching_the_form() {
    let (e, _) = engine();
    let table = Table::new(&e, "post").columns(["title", "author", "published"]);
    let html = render(&table, &list()).await;

    // Read the header row itself rather than guessing: `title` and `published` carry no label in
    // this fixture, so they render as their names; `author` has one.
    let head = html.split("<thead>").nth(1).unwrap().split("</thead>").next().unwrap();
    let order: Vec<&str> = ["title", "Author", "published", "body", "views", "status"]
        .into_iter()
        .filter(|h| head.contains(&format!(">{h}")))
        .collect();
    assert_eq!(order, ["title", "Author", "published"], "only these, in the order given");
    assert!(html.contains("First post"), "and their cells");
    assert!(!html.contains("hello"), "not the body column's: {html}");

    // The dialog still edits everything writable — `columns` is the table, `fields` is the form.
    let dialog = render(&table, &ViewState::from_query("edit=7")).await;
    assert!(dialog.contains(r#"id="f-body""#), "the form is unaffected: {dialog}");
}

#[tokio::test]
async fn an_unknown_column_is_refused_by_name() {
    let (e, _) = engine();
    let err = Table::new(&e, "post")
        .columns(["title", "ttile"])
        .render_for(&no_headers(), &list())
        .await
        .expect_err("a typo must not silently drop a column");
    let msg = err.to_string();
    assert!(msg.contains("cannot show column 'ttile'") && msg.contains("known:"), "{msg}");
}

#[tokio::test]
async fn a_row_can_be_marked_from_its_own_data() {
    let (e, _) = engine();
    let table = Table::new(&e, "post")
        .row_class(|row| match row["status"].as_str() {
            Some("draft") => "table-warning".into(),
            _ => String::new(),
        });
    let html = render(&table, &list()).await;
    assert!(html.contains(r#"<tr id="row-7" class="table-warning">"#), "{html}");

    // No closure, no attribute — a table that wants none pays nothing.
    let plain = render(&Table::new(&e, "post"), &list()).await;
    assert!(plain.contains(r#"<tr id="row-7">"#), "{plain}");
}

#[tokio::test]
async fn a_row_class_cannot_break_out_of_its_attribute() {
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post").row_class(|_| NASTY.to_string()), &list()).await;
    assert!(!html.contains("<script>"), "{html}");
}

// ---------- CSV: the menu, the dialog, the two ways in ----------

#[cfg(feature = "csv")]
#[tokio::test]
async fn csv_lives_in_a_menu_that_needs_no_javascript_to_open() {
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post"), &list()).await;
    // A `<details>` is the dropdown: the browser opens and closes it.
    assert!(html.contains(r#"<details class="rl-menu">"#), "{html}");
    assert!(html.contains("Export CSV") && html.contains("Import CSV"), "{html}");
    assert!(html.contains("format=csv") && html.contains("import=1"), "{html}");

    // A reader is offered the export and not the import.
    let (e, _) = engine_with(Arc::new(ReadOnlyGate));
    let html = render(&Table::new(&e, "post"), &list()).await;
    assert!(html.contains("Export CSV"), "reading is still reading: {html}");
    assert!(!html.contains("Import CSV"), "but importing is a write: {html}");
}

#[cfg(feature = "csv")]
#[tokio::test]
async fn the_import_dialog_offers_a_file_and_a_paste_box() {
    let (e, _) = engine();
    let html = render(&Table::new(&e, "post"), &ViewState::from_query("import=1")).await;
    assert!(html.contains("<dialog open"), "?import=1 opens it, like every other dialog: {html}");
    // Two independent actions, each with its own form and its own button: a file that goes
    // straight to the server…
    assert!(html.contains(r#"enctype="multipart/form-data""#), "{html}");
    assert!(html.contains(r#"type="file" name="file""#), "{html}");
    assert!(!html.contains("this.form.csv.value"), "and no JavaScript reading it first: {html}");
    // …and a paste, for the quick case.
    assert!(html.contains(r#"name="csv""#), "{html}");
    assert_eq!(html.matches(r#"name="_op" value="import""#).count(), 2, "one per form");
    // Each way in is headed and buttoned, and the divider says they are alternatives.
    assert!(html.contains("File import") && html.contains("Direct text import"), "{html}");
    assert!(html.contains(">Upload file</button>") && html.contains(">Import text</button>"), "{html}");
    assert!(html.contains(">or</span>"), "{html}");
    assert!(html.contains("id,title"), "the placeholder shows the columns an import reads");
    // No dialog for someone who may not write.
    let (e, _) = engine_with(Arc::new(ReadOnlyGate));
    let html = render(&Table::new(&e, "post"), &ViewState::from_query("import=1")).await;
    assert!(!html.contains("<dialog"), "{html}");
}

/// A body shaped the way a browser posts the dialog's upload form.
#[cfg(feature = "csv")]
fn upload(file: &[u8]) -> (HeaderMap, Vec<u8>) {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        "multipart/form-data; boundary=----B".parse().unwrap(),
    );
    let mut body = Vec::new();
    body.extend(b"------B\r\nContent-Disposition: form-data; name=\"_op\"\r\n\r\nimport\r\n");
    body.extend(
        b"------B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"rows.csv\"\r\n\r\n",
    );
    body.extend(file);
    body.extend(b"\r\n------B--\r\n");
    (headers, body)
}

#[cfg(feature = "csv")]
#[tokio::test]
async fn a_file_is_uploaded_to_the_server_and_applied() {
    let (e, log) = engine();
    let table = Table::new(&e, "post");
    let (headers, body) = upload(b"title,slug\nalpha,a\nbeta,b\n");
    let Outcome::Done(to) = table.submit(&headers, IP, &body, &list()).await.unwrap() else {
        panic!("this mock accepts writes");
    };
    assert_eq!(log.count(), 2, "both rows reached the backend as bytes, not via the browser");
    assert!(to.contains("done=imported:2,0"), "and the page says so: {to}");
}

#[cfg(feature = "csv")]
#[tokio::test]
async fn an_uploaded_file_that_is_not_utf8_is_refused_by_name() {
    // The operator can't see the file before it applies, so guessing an encoding would put mojibake
    // in the database unnoticed.
    let (e, log) = engine();
    let table = Table::new(&e, "post");
    let (headers, body) = upload(b"title,slug\nca\xe9,a\n"); // latin-1 'é'
    let Outcome::Invalid(state) = table.submit(&headers, IP, &body, &list()).await.unwrap() else {
        panic!("an unreadable file is a rejection");
    };
    assert_eq!(*state.mode(), Mode::Import);
    let html = table.render_for(&no_headers(), &state).await.unwrap();
    assert!(html.contains("isn&#39;t valid UTF-8") || html.contains("isn't valid UTF-8"), "{html}");
    assert_eq!(log.count(), 0, "and nothing was written");

    // A spreadsheet's UTF-8 BOM is stripped rather than treated as part of the first column name.
    let (headers, body) = upload("\u{feff}title,slug\nalpha,a\n".as_bytes());
    assert!(matches!(
        table.submit(&headers, IP, &body, &list()).await.unwrap(),
        Outcome::Done(_)
    ));
    assert_eq!(log.count(), 1);
}

#[cfg(feature = "csv")]
#[tokio::test]
async fn a_refused_import_comes_back_with_its_report_and_the_text_still_in_it() {
    // `title` is rejected by this mock, so every row fails — and an import is all-or-nothing, so
    // redirecting to an unchanged list would look like it had worked.
    let post = Mock::new("post", post_columns()).rejecting("title");
    let mut e = Engine::new();
    e.add(Arc::new(post), Arc::new(Open));
    for target in ["author", "tag"] {
        e.add(Arc::new(Mock::new(target, vec![field("id", false, true, None)]).rows(vec![])), Arc::new(Open));
    }
    let table = Table::new(&e, "post");
    let body = "_op=import&csv=title%2Cslug%0Aalpha%2Ca%0Abeta%2Cb%0A";
    let Outcome::Invalid(state) = table.submit(&no_headers(), IP, body.as_bytes(), &list()).await.unwrap()
    else {
        panic!("a rejected import is a rejection, not a redirect");
    };
    assert_eq!(*state.mode(), Mode::Import, "the import dialog reopens");

    let html = table.render_for(&no_headers(), &state).await.unwrap();
    assert!(html.contains("row(s) rejected — nothing was imported."), "{html}");
    assert!(html.contains("line 2:"), "each failure names its 1-based CSV line: {html}");
    assert!(html.contains("alpha,a"), "and the text is still there to fix: {html}");
}

#[cfg(feature = "csv")]
#[tokio::test]
async fn a_good_import_applies_and_returns_to_the_list() {
    let (e, log) = engine();
    let table = Table::new(&e, "post");
    let body = "_op=import&csv=title%2Cslug%0Aalpha%2Ca%0A";
    let Outcome::Done(to) = table.submit(&no_headers(), IP, body.as_bytes(), &ViewState::from_query("page=2")).await.unwrap()
    else {
        panic!("this mock accepts writes");
    };
    assert!(to.contains("page=2") && !to.contains("import=1"), "back to the list: {to}");
    assert!(to.contains("done=imported:1,0"), "with the report the alert renders: {to}");
    assert_eq!(log.count(), 1, "one batch reached the backend");
}

// ---------- widgets, one input each ----------

#[tokio::test]
async fn every_widget_override_renders_its_own_input() {
    let cols = vec![
        field("id", false, true, None),
        with_display("body", LogicalType::Text, vec![], Some(FieldDisplay::Textarea { rows: 8 })),
        with_display("mood", LogicalType::Text, vec!["good".into()], Some(FieldDisplay::Radio)),
        with_display("weight", LogicalType::Float, vec![], Some(FieldDisplay::Range { min: 0.0, max: 10.0, step: 0.5 })),
        with_display("contact", LogicalType::Text, vec![], Some(FieldDisplay::Email)),
        with_display("link", LogicalType::Text, vec![], Some(FieldDisplay::Url)),
        with_display("at", LogicalType::Int, vec![], Some(FieldDisplay::DateTime)),
        typed("count", LogicalType::Int, true),
        typed("ratio", LogicalType::Float, true),
        typed("on", LogicalType::Bool, false),
    ];
    let mut e = Engine::new();
    e.add(Arc::new(Mock::new("thing", cols)), Arc::new(Open));
    let html = Form::new(&e, "thing").render_for(&no_headers(), &list()).await.unwrap();
    for expect in [
        r#"name="body" rows="8""#,
        r#"type="radio" id="f-mood-good" name="mood""#,
r#"min="0" max="10" step="0.5""#,
        r#"type="email" name="contact""#,
        r#"type="url" name="link""#,
        r#"type="datetime-local" step="60" name="at""#,
        r#"type="number" step="1" name="count""#,
        r#"type="number" step="any" name="ratio""#,
        r#"type="checkbox" role="switch""#,
        r#"name="on" value="true""#,
    ] {
        assert!(html.contains(expect), "missing {expect}:\n{html}");
    }
    assert!(html.contains("<textarea"), "and prose gets a textarea");
}

#[tokio::test]
async fn a_relation_is_a_dropdown_until_its_target_outgrows_the_threshold() {
    let (e, _) = engine();
    let small = Form::new(&e, "post")
        .fields(["title", "slug", "author"])
        .render_for(&no_headers(), &list())
        .await
        .unwrap();
    assert!(small.contains(r#"<option value="3">Ada</option>"#), "two authors fit in a select: {small}");

    let big = Form::new(&e, "post")
        .fields(["title", "slug", "author"])
        .picker_threshold(1)
        .render_for(&no_headers(), &list())
        .await
        .unwrap();
    assert!(big.contains(r#"name="author" value="" placeholder="author id""#), "{big}");
    assert!(big.contains("too many to list"), "and it says why");
}

#[tokio::test]
async fn a_select_offers_a_blank_only_where_the_column_takes_one() {
    let cols = vec![
        field("id", false, true, None),
        Column::Field {
            name: "needed".into(),
            logical_type: LogicalType::Enum,
            read_only: false,
            write_only: false,
            nullable: false,
            required: true,
            options: vec!["a".into(), "b".into()],
            label: None,
            description: None,
            default: None,
            display: None,
            sortable: true,
        },
        Column::Field {
            name: "optional".into(),
            logical_type: LogicalType::Enum,
            read_only: false,
            write_only: false,
            nullable: true,
            required: false,
            options: vec!["a".into()],
            label: None,
            description: None,
            default: None,
            display: None,
            sortable: true,
        },
    ];
    let mut e = Engine::new();
    e.add(Arc::new(Mock::new("thing", cols)), Arc::new(Open));
    let html = Form::new(&e, "thing").render_for(&no_headers(), &list()).await.unwrap();
    let needed = html.split(r#"id="f-needed""#).nth(1).unwrap().split("</select>").next().unwrap();
    assert!(!needed.contains(r#"<option value="">"#), "a required column has no blank: {needed}");
    let optional = html.split(r#"id="f-optional""#).nth(1).unwrap().split("</select>").next().unwrap();
    assert!(optional.contains(r#"<option value="">—</option>"#), "{optional}");
}

#[tokio::test]
async fn a_required_field_is_marked_and_help_text_is_shown() {
    let mut cols = post_columns();
    cols[1] = Column::Field {
        name: "title".into(),
        logical_type: LogicalType::Text,
        read_only: false,
        write_only: false,
        nullable: false,
        required: true,
        options: Vec::new(),
        label: Some("Title".into()),
        description: Some("The headline.".into()),
        default: None,
        display: None,
        sortable: true,
    };
    let mut e = Engine::new();
    e.add(Arc::new(Mock::new("post", cols)), Arc::new(Open));
    for t in ["author", "tag"] {
        e.add(Arc::new(Mock::new(t, vec![field("id", false, true, None)]).rows(vec![])), Arc::new(Open));
    }
    let html = Form::new(&e, "post")
        .fields(["title", "slug"]) // `slug` is required too, and a create must be able to satisfy it
        .render_for(&no_headers(), &list())
        .await
        .unwrap();
    assert!(html.contains(r#"Title <span class="text-danger" title="Required">*</span>"#), "{html}");
    assert!(html.contains("The headline."), "the column's description is the field's help");
}

#[tokio::test]
async fn fields_narrows_and_orders_while_omit_subtracts() {
    let (e, _) = engine();
    let html = Form::new(&e, "post")
        .fields(["body", "title", "slug"])
        .render_for(&no_headers(), &list())
        .await
        .unwrap();
    let order: Vec<&str> = ["body", "title", "slug"]
        .into_iter()
        .filter(|f| html.contains(&format!(r#"id="f-{f}""#)))
        .collect();
    assert_eq!(order, vec!["body", "title", "slug"], "the given order is the rendered order");
    assert!(!html.contains(r#"id="f-views""#), "and nothing else is rendered");

    let omitted = Form::new(&e, "post").omit(["body", "secret"]).render_for(&no_headers(), &list()).await.unwrap();
    assert!(!omitted.contains(r#"id="f-body""#) && omitted.contains(r#"id="f-title""#), "{omitted}");
}

#[tokio::test]
async fn two_forms_for_one_entity_can_share_a_page() {
    let (e, _) = engine();
    let a = Form::new(&e, "post").dom_id("left").fields(["title", "slug"]).render_for(&no_headers(), &list()).await.unwrap();
    let b = Form::new(&e, "post").dom_id("right").fields(["title", "slug"]).render_for(&no_headers(), &list()).await.unwrap();
    assert!(a.contains(r#"id="left""#) && b.contains(r#"id="right""#));
}
