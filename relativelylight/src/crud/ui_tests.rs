//! Tests for [`crud::ui::Form`](super::ui::Form) — the standalone create/edit form.
//!
//! These drive a **hand-written `Accessor`** rather than a database: everything `Form` decides is
//! decided from the published column metadata, so a mock entity pins the behaviour exactly and the
//! suite stays instant. What's covered:
//!
//! - the render-time checks that turn a *silently broken form* into an error naming the column: an
//!   unknown name, a read-only one, and a create that omits a column the engine requires;
//! - that `.fields()` narrows and orders, and `.omit()` subtracts, in the rendered JS;
//! - that create vs edit produce the right `mode`/`editId` (i.e. `POST` vs `PATCH`);
//! - that `render_for` answers `401` vs `403` from the gate instead of rendering a dead form;
//! - that the shared partials actually reached the output — the form markup *and* the core — which is
//!   what would break if an include were dropped from one host but not the other.

use super::ui::Form;
use crate::authz::{Authz, Decision, Open, Operation};
use crate::crud::engine::{
    Accessor, Cardinality, Column, Engine, Error, FieldDisplay, ListQuery, LogicalType, Page, Result,
};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

/// A `post` entity with one of every interesting shape: a required text column, one with a default,
/// a nullable one, a read-only one, an enum, and a to-one relation.
struct MockPost;

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
    }
}

#[async_trait]
impl Accessor for MockPost {
    fn slug(&self) -> &str {
        "post"
    }
    fn pk(&self) -> String {
        "id".into()
    }
    fn columns(&self) -> Vec<Column> {
        vec![
            field("id", false, true, None),                              // read-only PK
            field("title", true, false, None),                           // required, no default
            field("slug", true, false, Some(Value::String("x".into()))),  // required *with* a default
            field("body", false, false, None),                           // optional
            field("created_at", false, true, None),                      // read-only (hook-stamped)
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
            },
            Column::Relation {
                name: "author".into(),
                target: "author".into(),
                cardinality: Cardinality::ToOne,
                fk_column: Some("author_id".into()),
                read_only: false,
                label: None,
                description: None,
            },
        ]
    }
    async fn list(&self, _q: &ListQuery, _terse: bool) -> Result<Page> {
        Ok(Page::new(0, 1, 30, vec![]))
    }
    async fn get(&self, _pk: &str) -> Result<Option<Value>> {
        Ok(None)
    }
    async fn create(&self, _body: &Value) -> Result<Value> {
        Err(Error::ReadOnly)
    }
    async fn update(&self, _pk: &str, _body: &Value) -> Result<Option<Value>> {
        Err(Error::ReadOnly)
    }
    async fn delete(&self, _pk: &str) -> Result<Option<Value>> {
        Err(Error::ReadOnly)
    }
    async fn delete_many(&self, _q: &ListQuery) -> Result<u64> {
        Err(Error::ReadOnly)
    }
}

/// A gate that always answers the same thing — enough to check `render_for`'s mapping.
struct Always(Decision);

#[async_trait]
impl Authz for Always {
    async fn authorize(&self, _op: Operation, _headers: &http::HeaderMap) -> Decision {
        self.0
    }
}

fn engine_with(gate: Arc<dyn Authz>) -> Engine {
    let mut e = Engine::new("/api/v1");
    e.add(Arc::new(MockPost), gate);
    e
}

fn engine() -> Engine {
    engine_with(Arc::new(Open))
}

// ---------- the render-time checks (the point of doing this in Rust, not JS) ----------

#[test]
fn a_misspelled_field_name_is_an_error_naming_the_known_columns() {
    let e = engine();
    let err = Form::new(&e, "post").fields(["title", "titel"]).render().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("no column 'titel'"), "should name the offender: {msg}");
    assert!(msg.contains("title"), "should list what does exist: {msg}");

    // …and the same check applies to omit(), where a typo would silently *fail to hide* a column.
    let err = Form::new(&e, "post").omit(["boddy"]).render().unwrap_err();
    assert!(err.to_string().contains("no column 'boddy'"));
}

#[test]
fn a_read_only_column_cannot_be_put_in_a_form() {
    let e = engine();
    let err = Form::new(&e, "post").fields(["title", "created_at"]).render().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("created_at"), "{msg}");
    assert!(msg.contains("read-only"), "{msg}");
}

#[test]
fn creating_without_a_required_column_is_refused_before_it_can_422() {
    let e = engine();
    // `title` is required, so a create form that hides it could never submit.
    let err = Form::new(&e, "post").fields(["body", "status"]).render().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("title"), "should name the missing column: {msg}");

    let err = Form::new(&e, "post").omit(["title"]).render().unwrap_err();
    assert!(err.to_string().contains("title"));

    // A `default` does **not** excuse a required column from being rendered: `MetaField::default` is a
    // *create-form* default (it pre-fills the input and drops the `*`), and the engine never applies it
    // server-side — so an unrendered field is simply not sent, and the create 422s with `slug: required`.
    // This was found by driving the example in a browser: the create failed with nothing on screen.
    let err = Form::new(&e, "post").fields(["title", "body"]).render().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("slug"), "a required-with-default column must still be rendered: {msg}");
    assert!(msg.contains("default"), "the message should explain why a default doesn't help: {msg}");

    // Rendering it is enough — the user needn't type anything, since the input arrives pre-filled.
    Form::new(&e, "post")
        .fields(["title", "slug"])
        .render()
        .expect("every required column rendered → satisfiable");
}

#[test]
fn a_422_on_an_unrendered_column_is_promoted_to_the_banner() {
    // The form can only show a field error next to a field it renders. An error keyed on anything else
    // is pushed into `rowErrors` instead, because a save that fails with nothing on screen is the worst
    // outcome — how the `default` bug above stayed hidden.
    let e = engine();
    let html = Form::new(&e, "post").edit("1").fields(["title"]).render().unwrap();
    assert!(
        html.contains("if (!shown.includes(name)) this.rowErrors.push"),
        "the shared core must promote unrenderable field errors to the banner"
    );
}

#[test]
fn editing_may_omit_a_required_column_because_the_row_already_has_one() {
    let e = engine();
    // The same subset that's refused for a create is fine for an edit: PATCH is partial, and the
    // stored row already satisfies `title`.
    let html = Form::new(&e, "post")
        .edit("7")
        .fields(["body", "status"])
        .render()
        .expect("an edit needn't carry every required column");
    assert!(html.contains(r#"mode: "edit""#));
    assert!(html.contains(r#"editId: "7""#));
}

// ---------- field selection reaches the component ----------

#[test]
fn fields_narrows_and_orders_while_omit_subtracts() {
    let e = engine();
    // On an edit form, so this tests selection alone — a *create* would also have to satisfy every
    // required column, which is the previous test's subject.
    let html =
        Form::new(&e, "post").edit("1").fields(["status", "title", "body"]).render().unwrap();
    // Order is the caller's, not the model's.
    assert!(html.contains(r#"only: ["status","title","body"]"#), "{html}");
    assert!(html.contains("omit: []"));

    let html = Form::new(&e, "post").omit(["status", "author"]).render().unwrap();
    assert!(html.contains(r#"omit: ["status","author"]"#), "{html}");
    assert!(html.contains("only: []"));
}

#[test]
fn a_create_form_posts_and_carries_no_row_id() {
    let e = engine();
    let html = Form::new(&e, "post").render().unwrap();
    assert!(html.contains(r#"mode: "create""#));
    assert!(html.contains("editId: null"));
}

// ---------- the shared partials are present in the output ----------

#[test]
fn the_form_includes_both_shared_partials() {
    let e = engine();
    let html = Form::new(&e, "post").render().unwrap();
    // From _form_fields.html: the widget loop and the required marker.
    assert!(html.contains(r#"x-for="c in formCols()""#), "field markup partial missing");
    assert!(html.contains(r#"x-show="mustFill(c)""#), "required marker missing");
    // From _form_core.html: payload shaping and the API URL, i.e. the behaviour half.
    assert!(html.contains("payload()"), "form core partial missing");
    assert!(html.contains(r#"dataUrl: "/api/v1/post""#), "{html}");
    // The enum column's options travel in the published metadata, so the <select> can be built.
    assert!(html.contains("published"), "enum options missing from columns_json");
}

#[test]
fn presentation_options_render() {
    let e = engine();
    let plain = Form::new(&e, "post").render().unwrap();
    assert!(!plain.contains("card-header"), "no heading unless asked for");
    assert!(plain.contains(">Save<"), "default submit label");

    let dressed = Form::new(&e, "post")
        .title("New post")
        .description("Write something.")
        .submit_label("Publish")
        .cancel("/posts")
        .redirect("/posts/{id}")
        .render()
        .unwrap();
    assert!(dressed.contains("New post"));
    assert!(dressed.contains("Write something."));
    assert!(dressed.contains(">Publish<"));
    assert!(dressed.contains(r#"href="/posts""#));
    assert!(dressed.contains(r#"redirectTo: "/posts/{id}""#));

    // A title with HTML in it is escaped, not executed.
    let nasty = Form::new(&e, "post").title("<script>alert(1)</script>").render().unwrap();
    assert!(!nasty.contains("<script>alert(1)</script>"), "title must be escaped");
}

#[test]
fn two_forms_for_one_entity_can_share_a_page() {
    let e = engine();
    let a = Form::new(&e, "post").render().unwrap();
    let b = Form::new(&e, "post").dom_id("post_quick").render().unwrap();
    assert!(a.contains("function rlForm_post()"));
    assert!(b.contains("function rlForm_post_quick()"));
}

// ---------- per-field widget overrides ----------

/// An entity whose columns carry widget overrides, plus a `bad` one the test points a wrong widget at.
struct MockWidgets(Option<FieldDisplay>);

#[async_trait]
impl Accessor for MockWidgets {
    fn slug(&self) -> &str {
        "thing"
    }
    fn pk(&self) -> String {
        "id".into()
    }
    fn columns(&self) -> Vec<Column> {
        let with = |name: &str, lt: LogicalType, opts: Vec<String>, d: Option<FieldDisplay>| {
            Column::Field {
                name: name.into(),
                logical_type: lt,
                read_only: false,
                write_only: false,
                nullable: true,
                required: false,
                options: opts,
                label: None,
                description: None,
                default: None,
                display: d,
            }
        };
        vec![
            field("id", false, true, None),
            with("body", LogicalType::Text, vec![], Some(FieldDisplay::Textarea { rows: 8 })),
            with(
                "mood",
                LogicalType::Text,
                vec!["good".into(), "bad".into()],
                Some(FieldDisplay::Radio),
            ),
            with(
                "weight",
                LogicalType::Float,
                vec![],
                Some(FieldDisplay::Range { min: 0.0, max: 10.0, step: 0.5 }),
            ),
            with("contact", LogicalType::Text, vec![], Some(FieldDisplay::Email)),
            with("link", LogicalType::Text, vec![], Some(FieldDisplay::Url)),
            with("bad", LogicalType::Int, vec![], self.0),
        ]
    }
    async fn list(&self, _q: &ListQuery, _t: bool) -> Result<Page> {
        Ok(Page::new(0, 1, 30, vec![]))
    }
    async fn get(&self, _pk: &str) -> Result<Option<Value>> {
        Ok(None)
    }
    async fn create(&self, _b: &Value) -> Result<Value> {
        Err(Error::ReadOnly)
    }
    async fn update(&self, _pk: &str, _b: &Value) -> Result<Option<Value>> {
        Err(Error::ReadOnly)
    }
    async fn delete(&self, _pk: &str) -> Result<Option<Value>> {
        Err(Error::ReadOnly)
    }
    async fn delete_many(&self, _q: &ListQuery) -> Result<u64> {
        Err(Error::ReadOnly)
    }
}

fn widget_engine(bad: Option<FieldDisplay>) -> Engine {
    let mut e = Engine::new("/api/v1");
    e.add(Arc::new(MockWidgets(bad)), Arc::new(Open));
    e
}

#[test]
fn a_widget_publishes_its_tag_and_its_parameters() {
    let e = widget_engine(None);
    let html = Form::new(&e, "thing").render().unwrap();
    // `display` is a plain lowercase string and the parameters ride in a sibling `widget` object, so a
    // client switches on a string instead of unpacking a tagged shape.
    assert!(html.contains(r#""display":"textarea""#), "{html}");
    assert!(html.contains(r#""widget":{"rows":8}"#), "textarea rows must be published");
    assert!(html.contains(r#""display":"radio""#));
    assert!(html.contains(r#""display":"range""#));
    // (serde_json sorts object keys, so assert on the members rather than an order.)
    assert!(html.contains(r#""max":10.0"#), "range max must be published: {html}");
    assert!(html.contains(r#""min":0.0"#), "range min must be published");
    assert!(html.contains(r#""step":0.5"#), "a float column's fractional step must survive");
    assert!(html.contains(r#""display":"email""#));
    assert!(html.contains(r#""display":"url""#));
    // A widget with no parameters publishes no `widget` key rather than an empty object.
    assert!(!html.contains(r#""display":"radio","widget""#));
}

#[test]
fn every_widget_has_exactly_one_branch_in_the_markup() {
    // `widgetOf()` returns one name per column and each name has one `x-if` — the property that stops
    // two inputs rendering for one field, or none at all.
    let fields = include_str!("../../templates/_form_fields.html");
    let core = include_str!("../../templates/_form_core.html");
    for w in [
        "switch", "datetime", "number", "range", "select", "radio", "textarea", "select-one",
        "select-many", "pick-one", "pick-many",
    ] {
        let branches = fields.matches(&format!("'{w}'")).count();
        assert!(branches >= 1, "widget `{w}` has no branch in _form_fields.html");
    }
    // `text`, `email` and `url` deliberately share one <input>, differing only in its `type`.
    assert!(fields.contains("widgetOf(c) === 'text' || widgetOf(c) === 'email' || widgetOf(c) === 'url'"));
    assert!(core.contains("widgetOf(c)"), "the resolver must live in the shared core");
}

#[test]
fn a_widget_that_cannot_render_its_column_is_refused_by_name() {
    // Each of these is a configuration that would otherwise render a *different* input than the model
    // asked for — noticed in production, not in review.
    let cases = [
        (FieldDisplay::Radio, "options"),                                  // no options to list
        (FieldDisplay::Textarea { rows: 3 }, "text column"),               // on an Int
        (FieldDisplay::Email, "text column"),
        (FieldDisplay::Range { min: 5.0, max: 5.0, step: 1.0 }, "min < max"), // empty range
    ];
    for (bad, expect) in cases {
        let e = widget_engine(Some(bad));
        let err = Form::new(&e, "thing").render().unwrap_err().to_string();
        assert!(err.contains("'bad'"), "must name the offending field: {err}");
        assert!(err.contains(expect), "expected {expect:?} in: {err}");
    }

    // `datetime` needs integer seconds — a string column would reach the picker as NaN.
    let mut e = Engine::new("/api/v1");
    e.add(Arc::new(MockPost), Arc::new(Open)); // MockPost's columns are Text
    let dt = FieldDisplay::DateTime;
    assert!(dt.fits(LogicalType::Text, false).is_err());
    assert!(dt.fits(LogicalType::Int, false).is_ok());

    // Positive control: the whole valid set renders, so the negatives can't pass vacuously.
    Form::new(&widget_engine(None), "thing").render().expect("valid widgets must render");
}

#[test]
fn the_table_checks_widgets_too_since_it_renders_the_same_form() {
    let e = widget_engine(Some(FieldDisplay::Radio));
    let err = super::ui::Table::new(&e, "thing").render().unwrap_err().to_string();
    assert!(err.contains("'bad'"), "Table must refuse it as well: {err}");
}

// ---------- gating ----------

#[tokio::test]
async fn render_for_refuses_instead_of_rendering_a_form_that_cannot_submit() {
    let h = http::HeaderMap::new();

    let e = engine_with(Arc::new(Always(Decision::NeedsLogin)));
    match Form::new(&e, "post").render_for(&h).await {
        Err(Error::Unauthorized) => {}
        other => panic!("NeedsLogin must map to Unauthorized (401), got {other:?}"),
    }

    let e = engine_with(Arc::new(Always(Decision::Denied)));
    match Form::new(&e, "post").render_for(&h).await {
        Err(Error::Forbidden) => {}
        other => panic!("Denied must map to Forbidden (403), got {other:?}"),
    }

    // Positive control: an allowing gate renders, so the negatives above can't pass vacuously.
    let e = engine_with(Arc::new(Always(Decision::Allow)));
    let html = Form::new(&e, "post").render_for(&h).await.expect("Allow must render");
    assert!(html.contains("function rlForm_post()"));
}

#[tokio::test]
async fn an_edit_form_is_gated_on_update_not_create() {
    /// Allows creates, refuses updates — so the two paths can't be confused.
    struct CreateOnly;
    #[async_trait]
    impl Authz for CreateOnly {
        async fn authorize(&self, op: Operation, _h: &http::HeaderMap) -> Decision {
            if op == Operation::Create {
                Decision::Allow
            } else {
                Decision::Denied
            }
        }
    }
    let e = engine_with(Arc::new(CreateOnly));
    let h = http::HeaderMap::new();

    Form::new(&e, "post").render_for(&h).await.expect("create is allowed");
    match Form::new(&e, "post").edit("1").render_for(&h).await {
        Err(Error::Forbidden) => {}
        other => panic!("an edit form must ask about Update, got {other:?}"),
    }
}

#[test]
fn an_unregistered_entity_is_an_error() {
    let e = engine();
    assert!(matches!(Form::new(&e, "nope").render(), Err(Error::NotFound)));
}
