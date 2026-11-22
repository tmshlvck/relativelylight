//! What an app sets per column and per relation: [`MetaField`], [`MetaRelation`] and the hook types
//! they hold. Backend-agnostic; [`MetaModel`](super::MetaModel) holds them.

use crate::crud::{Cardinality, FieldDisplay, LogicalType, ValidationErrors, Fmt, FmtCtx};
use serde_json::{Map, Value};

pub type Validator = Box<dyn Fn(&Value) -> std::result::Result<(), String> + Send + Sync>;
pub type WriteTransform = Box<dyn Fn(Value) -> Value + Send + Sync>;
pub type ReadTransform = Box<dyn Fn(&Value) -> Value + Send + Sync>;
pub type RowLabel = Box<dyn Fn(&Value) -> String + Send + Sync>;
pub type RowValidator =
    Box<dyn Fn(&Map<String, Value>) -> std::result::Result<(), ValidationErrors> + Send + Sync>;

/// A scalar field of an entity (config the user may tweak via `MetaModel::field`).
#[non_exhaustive]
pub struct MetaField {
    // Informational — set by introspection:
    pub name: String,
    pub logical_type: LogicalType,
    pub is_pk: bool,
    pub is_fk: bool,
    /// The allowed values, when the column is an enumeration — empty for everything else.
    ///
    /// **Introspected** from `ColumnType::Enum` — a `DeriveActiveEnum` with `db_type = "Enum"` — so an
    /// enum needs no per-model code, on SQLite as much as on Postgres/MySQL: the variants become a
    /// `<select>` (or a radio group) in the admin form and a membership check on write — a value
    /// outside the list is refused, where before *any* string was accepted. (On SQLite that column is
    /// plain text; on Postgres it is a real enum type, which must exist.)
    ///
    /// A `DeriveActiveEnum` with `db_type = "String"` is a text column as far as the schema is
    /// concerned, so there is nothing to introspect: take the list from the enum with
    /// [`options_from`](Self::options_from), or set it by hand —
    /// `model.field("status").options = vec!["draft".into(), "live".into()]`. Doing that on any text
    /// column turns it into a closed set — the check and the `<select>` key off this list, not off the
    /// logical type.
    ///
    /// Values are matched **exactly**; database enums are case-sensitive.
    pub options: Vec<String>,
    /// How an option is **shown**, `(stored value, label)` — `in_progress` as "In-Progress" — in
    /// forms, cells, the View dialog and filters. Display only: the database, URLs, CSV and the
    /// write check keep the stored value. An option without one shows as stored. See
    /// [`option_labels`](Self::option_labels) and [`options_from_display`](Self::options_from_display).
    pub option_labels: Vec<(String, String)>,
    /// Whether a write must carry a value for this column. Introspected as **NOT NULL, no default
    /// declared on the entity, and not the primary key** — the three facts that make an omission a
    /// database error rather than a legitimate blank.
    ///
    /// Enforced on **create** (a missing field → `422`, not the `500` the database would produce), and on
    /// any write that sends an explicit `null`. It means **present**, not non-empty: `""` still satisfies
    /// a NOT NULL text column, exactly as before — pair it with a `non_empty` validator if you want more.
    ///
    /// Set it to `false` to opt out. You need that when the *database* has a default the entity doesn't
    /// declare (`DEFAULT now()` written in DDL rather than `#[sea_orm(default_value = ..)]`) — SeaORM
    /// can't see it, so introspection assumes the column is required. Marking a field `read_only` or
    /// `hidden` also exempts it automatically, without touching this, since a caller then has no way to
    /// supply it — which is what spares a `created_at` filled by an `ActiveModelBehavior::before_save`
    /// hook, provided you marked it read-only (both examples do).
    pub required: bool,
    /// Whether the column accepts SQL NULL (read from the entity's `ColumnDef`). Published on the
    /// column, and it decides what an **empty** submitted input means — see
    /// [`blank_is_null`](Self::blank_is_null).
    pub nullable: bool,
    // Visibility — you may change these:
    pub read_only: bool,
    pub write_only: bool,
    /// Written when the row is created, never by an update: the edit form leaves the field out, and
    /// an update that carries it (an API call, a CSV import, a forged form) is refused with `422`.
    /// For a value whose later changes belong to a page of their own: `auth::user::meta_model` sets
    /// the first password this way, and every later one goes through the manager's reset, which
    /// also signs the account out.
    pub create_only: bool,
    pub hidden: bool,
    /// Whether the search box looks here (default `true`; a hidden or write-only field never).
    pub searchable: bool,
    // Presentation — optional:
    pub label: Option<String>,       // display label (defaults to the field name in the UI)
    pub description: Option<String>, // help text shown under the field in forms
    pub default: Option<Value>,      // create-form default value (edit uses the row)
    pub display: Option<FieldDisplay>, // presentation override (e.g. int-seconds → datetime)
    /// For a **nullable** text-ish column: store an empty submitted string as `NULL` rather than `""`
    /// (default `true`). A blank form input means "nothing here", and a column that is `NULL` for some
    /// rows and `""` for others is a trap for every later `is_some()` check. Set it `false` when an
    /// empty string is a value you mean to keep distinct from absent. Ignored on a `NOT NULL` column,
    /// where `""` is the only way to say "empty" (that's what keeps `MetaField::password()`'s
    /// blank-means-no-password behaviour working).
    pub blank_is_null: bool,
    // Optional user hooks:
    pub validate: Option<Validator>,
    /// The **storage codec**, inbound: the value a write carries → the value stored. Runs last on
    /// every surface (form, CSV, your own `Engine` calls), after coercion, `blank_is_null` and
    /// `validate`, so it sees the column's logical type — `MetaField::password` hashes here.
    ///
    /// Paired with [`on_read`](Self::on_read): if one is set, the other must undo it (a hash is the
    /// exception — a write-only column is never read back). See `on_read` for why.
    pub on_write: Option<WriteTransform>,
    /// The **storage codec**, outbound: the stored value → the value every read returns — the table,
    /// the View dialog, CSV export, your own `Engine::get`, **and the edit form**, which is filled
    /// from it. So it must be what [`on_write`](Self::on_write) accepts back: saving an untouched
    /// form writes `on_write(on_read(stored))`, and anything else silently rewrites the row.
    ///
    /// Which is why it is **not a display hook.** Masking a phone number here puts the mask in the
    /// edit form, and the next save stores it. Shape a value for the page with
    /// [`format_cell`](Self::format_cell) / [`format_view`](Self::format_view) (which no form
    /// sees); keep a secret out of reads altogether with [`write_only`](Self::write_only) or
    /// [`hidden`](Self::hidden).
    pub on_read: Option<ReadTransform>,
    /// The display formatter for a table's cells — see [`format_cell`](Self::format_cell).
    pub format_cell: Option<Fmt>,
    /// The display formatter where one row is shown — see [`format_view`](Self::format_view).
    pub format_view: Option<Fmt>,
}

impl MetaField {
    /// Configure this field as a **password**. In one call it becomes
    /// write-only (accepted on write, never returned in reads), labelled `"Password"` (unless you've
    /// already set a label), blank by default, and hashed with argon2id via an `on_write` hook — so
    /// the column stores a hash while the form takes plaintext. In the admin it renders as a masked
    /// input, and a blank value on *edit* keeps the current hash.
    ///
    /// An **empty value is stored as an empty hash**, which [`auth::verify_password`](crate::auth::verify_password)
    /// can never match — so password login is simply disabled for that account (e.g. an SSO / PassKey
    /// user). This is the whole setup:
    ///
    /// ```ignore
    /// let mut user = MetaModel::new(auth::user::Entity);
    /// user.field("password_hash").password();
    /// ```
    pub fn password(&mut self) -> &mut Self {
        self.write_only = true;
        self.label.get_or_insert_with(|| "Password".into());
        self.default = Some(Value::String(String::new()));
        self.on_write = Some(Box::new(|v| {
            let plain = v.as_str().unwrap_or("");
            if plain.is_empty() {
                Value::String(String::new()) // no password → empty hash → verify always fails
            } else {
                Value::String(crate::auth::hash_password(plain))
            }
        }));
        self
    }

    /// Render this integer column — which must hold **Unix seconds (UTC)** — as a datetime in the
    /// admin UI: the table cell shows a readable timestamp and the create/edit form uses a datetime
    /// picker — both in the caller's timezone, rendered server-side (see [`crate::time`]) — storing
    /// back the integer seconds. Storage and validation are unchanged (still an integer). For a
    /// read-only column (e.g. an auto-stamped `created_at`) this affects only the cell, since
    /// read-only fields have no input.
    ///
    /// ```ignore
    /// let mut zone = MetaModel::new(zone::Entity);
    /// zone.field("created_at").datetime();
    /// zone.field("expires_at").datetime(); // an editable timestamp → datetime picker
    /// ```
    pub fn datetime(&mut self) -> &mut Self {
        self.display = Some(FieldDisplay::DateTime);
        self
    }

    /// Edit this text column in a multi-line **`<textarea>`** of `rows` rows instead of a one-line
    /// input — for prose (a body, a note, a description). Table cells are unaffected.
    ///
    /// ```ignore
    /// post.field("body").textarea(8);
    /// ```
    pub fn textarea(&mut self, rows: u16) -> &mut Self {
        self.display = Some(FieldDisplay::Textarea { rows });
        self
    }

    /// Offer this column's [`options`](Self::options) as a **radio group** rather than a `<select>` —
    /// better for a handful of choices where seeing them all at once is the point. Set `options` first
    /// (or the render errors, since there'd be nothing to list).
    ///
    /// ```ignore
    /// post.field("status").options = vec!["draft".into(), "published".into()];
    /// post.field("status").radio();
    /// ```
    pub fn radio(&mut self) -> &mut Self {
        self.display = Some(FieldDisplay::Radio);
        self
    }

    /// Close this column over a **string-backed** `ActiveEnum`'s values — its `string_value`s, in
    /// declaration order — for a column the schema sees as text (`db_type = "String(..)"`, or a model
    /// field kept as `String`), where there are no variants to introspect. The list then can't drift
    /// from the Rust enum the way a hand-written one can.
    ///
    /// On SQLite, prefer `db_type = "Enum"` where you own the entity: it is still a text column, the
    /// variants are introspected, and this isn't needed. On Postgres it means a database enum type,
    /// migrated for each new variant — a text column with this is the alternative. Integer-backed
    /// enums have no labels to show, so they are not accepted.
    ///
    /// ```ignore
    /// post.field("status").options_from::<Status>();
    /// ```
    pub fn options_from<E>(&mut self) -> &mut Self
    where
        E: sea_orm::ActiveEnum<Value = String>,
    {
        self.options = E::values();
        self
    }

    /// Show these options as these labels — `("in_progress", "In-Progress")` — in forms, table
    /// cells, the View dialog, filter menus and chips. Display only: what is stored, put in a URL,
    /// exported and checked stays the value. Options left out show as stored. Replaces any labels
    /// set before.
    ///
    /// ```ignore
    /// order.field("state").option_labels([("new", "New"), ("in_progress", "In-Progress")]);
    /// ```
    pub fn option_labels<I, V, L>(&mut self, labels: I) -> &mut Self
    where
        I: IntoIterator<Item = (V, L)>,
        V: Into<String>,
        L: Into<String>,
    {
        self.option_labels = labels.into_iter().map(|(v, l)| (v.into(), l.into())).collect();
        self
    }

    /// The options **and** their labels from one string-backed enum: each variant's `string_value`,
    /// shown as its `Display`. SeaORM's `DeriveDisplay` writes that `Display`, with
    /// `#[sea_orm(display_value = "…")]` for a variant whose name won't do:
    ///
    /// ```ignore
    /// #[derive(Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, DeriveDisplay)]
    /// #[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "order_state")]
    /// pub enum State {
    ///     #[sea_orm(string_value = "new")] New,                                         // "New"
    ///     #[sea_orm(string_value = "in_progress", display_value = "In-Progress")] InProgress,
    ///     #[sea_orm(string_value = "done")] Done,                                       // "Done"
    /// }
    /// order.field("state").options_from_display::<State>();
    /// ```
    pub fn options_from_display<E>(&mut self) -> &mut Self
    where
        E: sea_orm::ActiveEnum<Value = String> + std::fmt::Display,
    {
        self.options = E::values();
        self.option_labels = E::iter().map(|v| (v.to_value(), v.to_string())).collect();
        self
    }

    /// Edit this numeric column with a **slider** over `min..=max`. `step` may be fractional for a
    /// float column. Table cells still show the number.
    ///
    /// ```ignore
    /// server.field("weight").range(0.0, 100.0, 1.0);
    /// ```
    pub fn range(&mut self, min: f64, max: f64, step: f64) -> &mut Self {
        self.display = Some(FieldDisplay::Range { min, max, step });
        self
    }

    /// Use `<input type="email">` for this text column: the browser's own check and the right mobile
    /// keyboard. That check is a **convenience, not the control** — pair it with a server-side
    /// validator, which is the thing that actually runs:
    ///
    /// ```ignore
    /// user.field("email").email();
    /// user.field("email").validate_str(relativelylight::validate::email);
    /// ```
    pub fn email(&mut self) -> &mut Self {
        self.display = Some(FieldDisplay::Email);
        self
    }

    /// Use `<input type="url">` for this text column, as [`email`](Self::email) but for links (pair it
    /// with [`validate::url`](crate::validate::url)).
    pub fn url(&mut self) -> &mut Self {
        self.display = Some(FieldDisplay::Url);
        self
    }

    /// Canonicalize an empty submitted string on a **nullable** text-ish column to `null` (see
    /// [`blank_is_null`](Self::blank_is_null)). Runs right after coercion, so validators and
    /// `on_write` hooks — and the row that lands in the database — all see one representation of
    /// "nothing here" instead of `NULL` for some writers and `""` for others.
    pub(super) fn normalize_blank(&self, v: Value) -> Value {
        let blankable = matches!(
            self.logical_type,
            LogicalType::Text | LogicalType::Uuid | LogicalType::Date | LogicalType::DateTime
        );
        match &v {
            Value::String(s) if self.nullable && self.blank_is_null && blankable && s.is_empty() => {
                Value::Null
            }
            _ => v,
        }
    }

    /// The membership error for an enum column, if the submitted value isn't one of [`options`]. `None`
    /// when the column is not an enumeration, or the value is `null` (absence is
    /// [`required`](MetaField::required)'s business, not this one).
    ///
    /// [`options`]: MetaField::options
    pub(super) fn options_error(&self, v: &Value) -> Option<String> {
        if self.options.is_empty() || v.is_null() {
            return None;
        }
        let ok = v.as_str().is_some_and(|s| self.options.iter().any(|o| o == s));
        (!ok).then(|| format!("must be one of: {}", self.options.join(", ")))
    }

    /// How this field is shown in a **table's cells**: a closure from [`FmtCtx`] (the value, the
    /// row and the request's headers) to **HTML, inserted verbatim**. Every table of the entity
    /// uses it — its own page, `Admin`, an accounts panel — but not a picker's list, where a click
    /// chooses a row. **Escape every value** with [`esc`](crate::crud::esc): an unescaped one
    /// is a stored XSS.
    ///
    /// Display only: the edit form, CSV, search and sort see the stored value. Independent of
    /// [`format_view`](Self::format_view) — for the same rendering in both, pass the same closure
    /// to each.
    ///
    /// ```ignore
    /// use relativelylight::crud::{esc, truncate};
    /// post.field("body").format_cell(truncate(60));   // a corner in the table, all of it in View
    /// ```
    pub fn format_cell<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&FmtCtx) -> String + Send + Sync + 'static,
    {
        self.format_cell = Some(Fmt::new(f));
        self
    }

    /// How this field is shown where **one row** is: a table's View dialog, and the dialog a
    /// relation's link opens (`Engine::picker_view`) — the same closure shape and the same rule
    /// (**escape every value**) as [`format_cell`](Self::format_cell), and independent of it.
    ///
    /// A link to the record's own page belongs here, with `target="_top"`: in a linked row's
    /// dialog, an `<iframe>`, it takes the whole window rather than loading the page inside the
    /// dialog. Mark it as leaving the page (`→`), so it is told apart from a relation's label,
    /// which opens a dialog:
    ///
    /// ```ignore
    /// workorder.field("number").format_view(|cx| format!(
    ///     r#"<a href="/work-orders/{}" target="_top">{}</a> →"#,
    ///     esc(&cx.row()["id"]), esc(cx.value()),
    /// ));
    /// ```
    pub fn format_view<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&FmtCtx) -> String + Send + Sync + 'static,
    {
        self.format_view = Some(Fmt::new(f));
        self
    }

    /// Attach a string [validator](crate::validate) — sugar over setting [`validate`](Self::validate)
    /// via [`validate::field::str_field`](crate::validate::field::str_field):
    ///
    /// ```ignore
    /// use relativelylight::validate;
    /// model.field("value").validate_str(validate::ipv4);
    /// model.field("target").validate_str(validate::all_of(vec![
    ///     Box::new(validate::non_empty), Box::new(validate::fqdn)]));
    /// ```
    pub fn validate_str<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&str) -> std::result::Result<(), String> + Send + Sync + 'static,
    {
        self.validate = Some(crate::validate::field::str_field(f));
        self
    }

    /// Attach an integer [validator](crate::validate) — sugar over setting [`validate`](Self::validate)
    /// via [`validate::field::int_field`](crate::validate::field::int_field):
    /// `model.field("priority").validate_int(validate::int_range(0, 65535))`.
    pub fn validate_int<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(i64) -> std::result::Result<(), String> + Send + Sync + 'static,
    {
        self.validate = Some(crate::validate::field::int_field(f));
        self
    }
}

/// A relation of an entity, as the app configures it. **`#[non_exhaustive]`** — reach one through
/// [`MetaModel::relation`](crate::crud::MetaModel::relation) and assign, as with [`MetaField`].
#[non_exhaustive]
pub struct MetaRelation {
    pub name: String,
    pub target: String, // target table name (the engine maps it to the target's slug)
    pub cardinality: Cardinality,
    pub owns_fk: bool,
    pub fk_column: Option<String>,
    pub read_only: bool,
    pub hidden: bool,
    /// Whether the search box matches this relation's labels (default `true`).
    pub searchable: bool,
    pub label: Option<String>,
    pub description: Option<String>,
    /// Whether this relation's labels link to their rows, viewed in a dialog — see
    /// [`links`](MetaRelation::links). `None`: as `Engine::picker_view` says.
    pub links: Option<bool>,
    /// Whether this relation's field offers "+ New" — see [`create`](MetaRelation::create).
    /// `None`: as the target's `MetaModel::picker_create`, else `Engine::picker_create`, says.
    pub create: Option<bool>,
    /// How many target rows this relation's input lists — see
    /// [`picker_threshold`](MetaRelation::picker_threshold). `None`: as `Engine::picker_threshold`.
    pub picker_threshold: Option<u64>,
    pub(super) from_col: String,
    pub(super) to_col: String,
    pub(super) is_nm: bool,
}

impl MetaRelation {
    /// A relation with every setting at its default: writable, shown, searchable, owning no FK and
    /// joining on no column — what introspection and [`relate`](super::MetaModel::relate) start from.
    pub(super) fn base(name: String, target: String, cardinality: Cardinality) -> Self {
        Self {
            name,
            target,
            cardinality,
            owns_fk: false,
            fk_column: None,
            read_only: false,
            hidden: false,
            searchable: true,
            label: None,
            description: None,
            links: None,
            create: None,
            picker_threshold: None,
            from_col: String::new(),
            to_col: String::new(),
            is_nm: false,
        }
    }

    /// Link this relation's labels to their rows (a dialog with the row, and Edit), or not —
    /// whatever `Engine::picker_view` says for the rest. `true` turns it on for this relation alone,
    /// with the app-wide switch off; `false` keeps it off here while it is on elsewhere. Either way
    /// the target's gate still decides per caller (read for the link, update for Edit), and it
    /// needs `Engine::picker_path`.
    ///
    /// ```ignore
    /// post.relation("author").links(true);   // only a post's author links, nothing else does
    /// ```
    pub fn links(&mut self, on: bool) -> &mut Self {
        self.links = Some(on);
        self
    }

    /// Offer "+ New" on this relation's field, or not — whatever the target's
    /// [`MetaModel::picker_create`](crate::crud::MetaModel::picker_create) and `Engine::picker_create` say for the rest. `true` turns it on here alone; `false` keeps it off
    /// here (say, an invoicing contact that must be an existing one) while the airline beside it
    /// has it. The target's gate still decides per caller (create and list), and it needs
    /// `Engine::picker_path` and a `POST` on its route.
    ///
    /// ```ignore
    /// workorder.relation("airline").create(true);
    /// workorder.relation("invoice_contact").create(false);
    /// ```
    pub fn create(&mut self, on: bool) -> &mut Self {
        self.create = Some(on);
        self
    }

    /// How many target rows this relation's form input may list as a `<select>` (a multi-select
    /// for a to-many) before it shows the selection and edits it in the picker's dialog — overriding
    /// `Engine::picker_threshold` (default 50) for this relation. Without `Engine::picker_path` the
    /// input stays a `<select>` of every row.
    ///
    /// ```ignore
    /// workorder.relation("aircraft").picker_threshold(200);   // registrations are quick to scan
    /// ```
    pub fn picker_threshold(&mut self, n: u64) -> &mut Self {
        self.picker_threshold = Some(n);
        self
    }
}

