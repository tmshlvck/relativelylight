//! SeaORM backend flavor: introspection + the `MetaModel` builder + an `Accessor` implementation.
//! This is the only module that depends on SeaORM.

use crate::crud::engine::{
    BatchApplied,
    coerce, default_label, slugify, value_key, Accessor, Cardinality, Column, Engine, Error,
    FieldDisplay, ListQuery, LogicalType, Page, Result, RowItem, ValidationErrors,
};
use async_trait::async_trait;
use sea_orm::sea_query::{Alias, DynIden, Expr, Query, TableRef};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ColumnType, Condition, ConnectionTrait, DatabaseConnection,
    DbErr, EntityName, EntityTrait, IdenStatic, Identity, IntoActiveModel, Iterable, ModelTrait,
    Order, PaginatorTrait, PrimaryKeyToColumn, QueryFilter, QueryOrder, QuerySelect, QueryTrait,
    Related, RelationTrait, RelationType, SqlErr, TransactionTrait, Value as DbValue,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use std::sync::{Arc, RwLock, Weak};

impl From<DbErr> for Error {
    fn from(e: DbErr) -> Self {
        // Classify DB constraint violations portably (SQLite / Postgres / …) via SeaORM's `sql_err`
        // so the engine can return 409 instead of a generic 500.
        match e.sql_err() {
            Some(SqlErr::UniqueConstraintViolation(msg)) => Error::Conflict(msg),
            Some(SqlErr::ForeignKeyConstraintViolation(msg)) => Error::Conflict(msg),
            _ => Error::Backend(e.to_string()),
        }
    }
}

// ---- Builder config (the SeaORM `MetaModel`'s per-field/relation config) ----

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
    /// **Introspected** from `ColumnType::Enum`, so a Postgres/MySQL enum needs no per-model code: the
    /// variants become a `<select>` in the admin form, an `enum` in the OpenAPI schema, and a membership
    /// check on write (a value outside the list is a `422`, where before *any* string was accepted).
    ///
    /// **Set it by hand for the common SQLite shape.** A `DeriveActiveEnum` with `db_type = "String"` is a
    /// text column as far as the schema is concerned, so there is nothing to introspect:
    /// `model.field("status").options = vec!["draft".into(), "live".into()]`. Doing that on any text
    /// column turns it into a closed set — the check and the `<select>` key off this list, not off the
    /// logical type.
    ///
    /// Values are matched **exactly**; database enums are case-sensitive.
    pub options: Vec<String>,
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
    /// Whether the column accepts SQL NULL (read from the entity's `ColumnDef`). Reported in the
    /// metadata + OpenAPI schema, and it decides what an **empty** submitted string means — see
    /// [`blank_is_null`](Self::blank_is_null).
    pub nullable: bool,
    // Visibility — you may change these:
    pub read_only: bool,
    pub write_only: bool,
    pub hidden: bool,
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
    pub on_write: Option<WriteTransform>,
    pub on_read: Option<ReadTransform>,
}

impl MetaField {
    /// Configure this field as a **password** (requires the `auth` feature). In one call it becomes
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
    #[cfg(feature = "auth")]
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
    /// admin UI: the table cell shows a readable UTC timestamp and the create/edit form uses a
    /// datetime picker (edited in UTC), storing back the integer seconds. Storage, validation, and
    /// the OpenAPI schema are unchanged (still an integer). For a read-only column (e.g. an
    /// auto-stamped `created_at`) this affects only the cell, since read-only fields have no input.
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
    fn normalize_blank(&self, v: Value) -> Value {
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

    /// Attach a string [validator](crate::validate) — sugar over setting [`validate`](Self::validate)
    /// via [`validate::field::str_field`](crate::validate::field::str_field):
    ///
    /// ```ignore
    /// use relativelylight::validate;
    /// model.field("value").validate_str(validate::ipv4);
    /// model.field("target").validate_str(validate::all_of(vec![
    ///     Box::new(validate::non_empty), Box::new(validate::fqdn)]));
    /// ```
    /// The membership error for an enum column, if the submitted value isn't one of [`options`]. `None`
    /// when the column is not an enumeration, or the value is `null` (absence is
    /// [`required`](MetaField::required)'s business, not this one).
    ///
    /// [`options`]: MetaField::options
    fn options_error(&self, v: &Value) -> Option<String> {
        if self.options.is_empty() || v.is_null() {
            return None;
        }
        let ok = v.as_str().is_some_and(|s| self.options.iter().any(|o| o == s));
        (!ok).then(|| format!("must be one of: {}", self.options.join(", ")))
    }

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

/// A relation of an entity (config the user may tweak via `MetaModel::relation`).
/// Per-relation config. **`#[non_exhaustive]`** — reach one through
/// [`MetaModel::relation`](MetaModel::relation) and assign, as with [`MetaField`].
#[non_exhaustive]
pub struct MetaRelation {
    pub name: String,
    pub target: String, // target table name (the engine maps it to the target's slug)
    pub cardinality: Cardinality,
    pub owns_fk: bool,
    pub fk_column: Option<String>,
    pub read_only: bool,
    pub hidden: bool,
    pub label: Option<String>,
    pub description: Option<String>,
    from_col: String,
    to_col: String,
    is_nm: bool,
}

// ---- Introspection helpers ----

/// The variants of an enum column, in declaration order — empty for any other type. `ColumnType` is
/// `#[non_exhaustive]` upstream, hence the wildcard.
fn enum_variants(ct: &ColumnType) -> Vec<String> {
    match ct {
        ColumnType::Enum { variants, .. } => variants.iter().map(|v| v.to_string()).collect(),
        _ => Vec::new(),
    }
}

fn logical_type(ct: &ColumnType) -> LogicalType {
    match ct {
        ColumnType::Char(_) | ColumnType::String(_) | ColumnType::Text => LogicalType::Text,
        ColumnType::TinyInteger
        | ColumnType::SmallInteger
        | ColumnType::Integer
        | ColumnType::BigInteger
        | ColumnType::TinyUnsigned
        | ColumnType::SmallUnsigned
        | ColumnType::Unsigned
        | ColumnType::BigUnsigned => LogicalType::Int,
        ColumnType::Float | ColumnType::Double | ColumnType::Decimal(_) => LogicalType::Float,
        ColumnType::Boolean => LogicalType::Bool,
        ColumnType::Date => LogicalType::Date,
        ColumnType::DateTime
        | ColumnType::Timestamp
        | ColumnType::TimestampWithTimeZone
        | ColumnType::Time => LogicalType::DateTime,
        ColumnType::Uuid => LogicalType::Uuid,
        ColumnType::Json | ColumnType::JsonBinary => LogicalType::Json,
        ColumnType::Enum { .. } => LogicalType::Enum,
        _ => LogicalType::Other,
    }
}

fn iden_name(d: &DynIden) -> String {
    let mut s = String::new();
    d.unquoted(&mut s);
    s
}

fn first_identity_col(id: &Identity) -> String {
    match id {
        Identity::Unary(a) => iden_name(a),
        Identity::Binary(a, _) => iden_name(a),
        Identity::Ternary(a, _, _) => iden_name(a),
        _ => String::new(),
    }
}

fn table_ref_name(t: &TableRef) -> String {
    match t {
        TableRef::Table(a) => iden_name(a),
        TableRef::SchemaTable(_, b) => iden_name(b),
        TableRef::DatabaseSchemaTable(_, _, c) => iden_name(c),
        TableRef::TableAlias(a, _) => iden_name(a),
        TableRef::SchemaTableAlias(_, b, _) => iden_name(b),
        TableRef::DatabaseSchemaTableAlias(_, _, c, _) => iden_name(c),
        _ => String::new(),
    }
}

fn pk_names<E: EntityTrait>() -> Vec<String> {
    <E::PrimaryKey as Iterable>::iter()
        .map(|k| k.into_column().as_str().to_string())
        .collect()
}

fn column<E: EntityTrait>(name: &str) -> Option<E::Column> {
    <E::Column as Iterable>::iter().find(|c| c.as_str().eq_ignore_ascii_case(name))
}

fn pk_condition<E: EntityTrait>(pk: &str) -> Result<Condition> {
    let cols: Vec<E::Column> = <E::PrimaryKey as Iterable>::iter().map(|k| k.into_column()).collect();
    let parts: Vec<&str> = pk.split(',').collect();
    if parts.len() != cols.len() {
        return Err(Error::BadRequest(format!(
            "expected {} primary-key part(s), got {}",
            cols.len(),
            parts.len()
        )));
    }
    let mut cond = Condition::all();
    for (c, part) in cols.iter().zip(parts) {
        cond = cond.add(c.eq(str_to_db(c.def().get_column_type(), part)));
    }
    Ok(cond)
}

/// An integer → the ORM value variant matching the column's *actual* width/signedness, so a value
/// written to a `BigInteger`/`Unsigned`/… column has the right `Value` variant (SeaORM type-checks
/// the variant against the column on `set`). Falls back to `Int` (i32) for non-integer column types.
fn int_to_db(ct: &ColumnType, n: i64) -> DbValue {
    match ct {
        ColumnType::TinyInteger => DbValue::from(n as i8),
        ColumnType::SmallInteger => DbValue::from(n as i16),
        ColumnType::Integer => DbValue::from(n as i32),
        ColumnType::BigInteger => DbValue::from(n),
        ColumnType::TinyUnsigned => DbValue::from(n as u8),
        ColumnType::SmallUnsigned => DbValue::from(n as u16),
        ColumnType::Unsigned => DbValue::from(n as u32),
        ColumnType::BigUnsigned => DbValue::from(n as u64),
        _ => DbValue::from(n as i32),
    }
}

/// A typed NULL for an integer column (the `Value` variant must still match the column type).
fn int_null(ct: &ColumnType) -> DbValue {
    match ct {
        ColumnType::TinyInteger => DbValue::TinyInt(None),
        ColumnType::SmallInteger => DbValue::SmallInt(None),
        ColumnType::BigInteger => DbValue::BigInt(None),
        ColumnType::TinyUnsigned => DbValue::TinyUnsigned(None),
        ColumnType::SmallUnsigned => DbValue::SmallUnsigned(None),
        ColumnType::Unsigned => DbValue::Unsigned(None),
        ColumnType::BigUnsigned => DbValue::BigUnsigned(None),
        _ => DbValue::Int(None),
    }
}

/// JSON value → ORM value (for writes), by column type.
fn json_to_db(ct: &ColumnType, v: &Value) -> DbValue {
    if v.is_null() {
        return match logical_type(ct) {
            LogicalType::Int => int_null(ct),
            LogicalType::Float => DbValue::Double(None),
            LogicalType::Bool => DbValue::Bool(None),
            _ => DbValue::String(None),
        };
    }
    match logical_type(ct) {
        LogicalType::Int => v.as_i64().map(|n| int_to_db(ct, n)).unwrap_or_else(|| int_null(ct)),
        LogicalType::Float => v.as_f64().map(DbValue::from).unwrap_or(DbValue::Double(None)),
        LogicalType::Bool => DbValue::from(v.as_bool().unwrap_or(false)),
        _ => DbValue::from(v.as_str().unwrap_or_default().to_string()),
    }
}

/// String (URL value) → ORM value, by column type.
fn str_to_db(ct: &ColumnType, s: &str) -> DbValue {
    match logical_type(ct) {
        LogicalType::Int => s.parse::<i64>().map(|n| int_to_db(ct, n)).unwrap_or_else(|_| DbValue::from(s.to_string())),
        LogicalType::Float => s.parse::<f64>().map(DbValue::from).unwrap_or_else(|_| DbValue::from(s.to_string())),
        LogicalType::Bool => DbValue::from(matches!(s, "true" | "1")),
        _ => DbValue::from(s.to_string()),
    }
}

/// A junction primary-key value (int or string) → ORM value.
fn key_to_db(v: &Value) -> DbValue {
    if let Some(n) = v.as_i64() {
        DbValue::from(n)
    } else if v.is_null() {
        DbValue::Int(None)
    } else {
        DbValue::from(value_key(v))
    }
}

fn pk_string(pk: &[String], full: &Value) -> String {
    pk.iter()
        .map(|c| value_key(full.get(c).unwrap_or(&Value::Null)))
        .collect::<Vec<_>>()
        .join(",")
}

// ---- N:M read resolver (typed find_related) ----

#[async_trait]
trait NmResolver: Send + Sync {
    async fn read(&self, db: &DatabaseConnection, source_pk: &str) -> Result<Vec<Value>>;
}

struct RelatedResolver<E, T> {
    target: T,
    _pd: PhantomData<E>,
}

#[async_trait]
impl<E, T> NmResolver for RelatedResolver<E, T>
where
    E: EntityTrait + Related<T> + Send + Sync + 'static,
    E::Model: ModelTrait<Entity = E> + Send + Sync,
    T: EntityTrait + Copy + Send + Sync + 'static,
    T::Model: Serialize + Send + Sync,
{
    async fn read(&self, db: &DatabaseConnection, source_pk: &str) -> Result<Vec<Value>> {
        let Some(src) = E::find().filter(pk_condition::<E>(source_pk)?).one(db).await? else {
            return Ok(vec![]);
        };
        let rows = src.find_related(self.target).all(db).await?;
        Ok(rows.iter().map(|m| serde_json::to_value(m).unwrap()).collect())
    }
}

struct Nm {
    resolver: Arc<dyn NmResolver>,
    junction: String,
    source_col: String,
    target_col: String,
}

// ---- Cross-entity registry (keeps relations resolvable inside the backend) ----

/// The minimal capability one entity needs from a *sibling* entity to resolve a relation into a
/// `{id, label}` link: fetch a raw row (or rows) and label it. Implemented by `SeaAccessor` for
/// itself. Note these return **raw** model rows (no relation resolution) — resolving a link must not
/// recurse into the target's own relations.
#[async_trait]
trait SeaRow: Send + Sync {
    fn slug(&self) -> &str;
    fn pk_col(&self) -> String;
    fn label_of(&self, raw: &Value) -> String;
    async fn get_raw(&self, pk: &str) -> Result<Option<Value>>;
    async fn list_by(&self, col: &str, val: &Value) -> Result<Vec<Value>>;
}

/// Table-name → sibling row source. Holds `Weak` refs (the strong `Arc`s live in the `Engine` as
/// `dyn Accessor`), so there's no reference cycle and nothing to free explicitly.
#[derive(Default)]
struct SeaRegistry {
    rows: RwLock<BTreeMap<String, Weak<dyn SeaRow>>>,
}

impl SeaRegistry {
    fn insert(&self, table: &str, w: Weak<dyn SeaRow>) {
        self.rows.write().unwrap().insert(table.to_string(), w);
    }
    fn by_table(&self, table: &str) -> Option<Arc<dyn SeaRow>> {
        self.rows.read().unwrap().get(table).and_then(Weak::upgrade)
    }
    fn slug_for(&self, table: &str) -> Option<String> {
        self.by_table(table).map(|r| r.slug().to_string())
    }
}

/// Build a `{id, label}` relation link from a raw target row. Just identity + label — no URL.
fn link(target: Option<&dyn SeaRow>, raw: &Value) -> Value {
    match target {
        Some(t) => {
            let id = raw.get(t.pk_col()).cloned().unwrap_or(Value::Null);
            json!({ "id": id, "label": t.label_of(raw) })
        }
        None => {
            let id = raw.get("id").cloned().unwrap_or(Value::Null);
            json!({ "id": id, "label": default_label(raw) })
        }
    }
}

// ---- MetaModel builder ----

pub struct MetaModel<E: EntityTrait> {
    /// Public identifier / URL segment. Defaults to `slugify(table_name)`; override before register.
    pub slug: String,
    pub row_label: RowLabel,
    pub validate_row: Option<RowValidator>,
    table: String,
    fields: Vec<MetaField>,
    relations: Vec<MetaRelation>,
    nm: HashMap<String, Nm>,
    pk: Vec<String>,
    entity: E,
}

impl<E: EntityTrait + EntityName> MetaModel<E> {
    pub fn new(entity: E) -> Self {
        let table = entity.table_name().to_string();
        let slug = slugify(&table);
        let pk = pk_names::<E>();

        let raw = introspect_relations::<E>();
        let fk_cols: Vec<String> = raw.iter().filter(|r| r.owns_fk).map(|r| r.from_col.clone()).collect();

        let fields = <E::Column as Iterable>::iter()
            .map(|c| {
                let name = c.as_str().to_string();
                let is_pk = pk.contains(&name);
                let is_fk = fk_cols.contains(&name);
                let def = c.def();
                MetaField {
                    logical_type: logical_type(def.get_column_type()),
                    options: enum_variants(def.get_column_type()),
                    // NOT NULL, nothing to fall back on, and not the key the database assigns.
                    required: !def.is_null() && def.get_column_default().is_none() && !is_pk,
                    nullable: def.is_null(),
                    blank_is_null: true,
                    read_only: is_pk,
                    write_only: false,
                    hidden: is_fk,
                    is_pk,
                    is_fk,
                    name,
                    label: None,
                    description: None,
                    default: None,
                    display: None,
                    validate: None,
                    on_write: None,
                    on_read: None,
                }
            })
            .collect();

        let relations = raw
            .into_iter()
            .map(|r| MetaRelation {
                fk_column: r.owns_fk.then(|| r.from_col.clone()),
                read_only: !r.owns_fk,
                hidden: false,
                label: None,
                description: None,
                name: r.name,
                target: r.target,
                cardinality: r.cardinality,
                owns_fk: r.owns_fk,
                from_col: r.from_col,
                to_col: r.to_col,
                is_nm: false,
            })
            .collect();

        Self {
            slug,
            row_label: Box::new(default_label),
            validate_row: None,
            table,
            fields,
            relations,
            nm: HashMap::new(),
            pk,
            entity,
        }
    }

    pub fn fields(&self) -> impl Iterator<Item = &MetaField> {
        self.fields.iter()
    }
    pub fn field(&mut self, name: &str) -> &mut MetaField {
        self.fields.iter_mut().find(|f| f.name == name).unwrap_or_else(|| panic!("no field '{name}'"))
    }
    pub fn relations(&self) -> impl Iterator<Item = &MetaRelation> {
        self.relations.iter()
    }
    pub fn relation(&mut self, name: &str) -> &mut MetaRelation {
        self.relations.iter_mut().find(|r| r.name == name).unwrap_or_else(|| panic!("no relation '{name}'"))
    }

    /// Declare a relation to another model (required for N:M). Chainable.
    pub fn relate<T>(&mut self, other: &MetaModel<T>) -> &mut Self
    where
        E: Related<T> + Send + Sync + 'static,
        E::Model: ModelTrait<Entity = E> + Send + Sync,
        T: EntityTrait + EntityName + Copy + Send + Sync + 'static,
        T::Model: Serialize + Send + Sync,
    {
        let to = <E as Related<T>>::to();
        let via = <E as Related<T>>::via();
        let junction = table_ref_name(&to.from_tbl);
        let target_col = first_identity_col(&to.from_col);
        let source_col = via.as_ref().map(|d| first_identity_col(&d.to_col)).unwrap_or_default();

        self.nm.insert(
            other.slug.clone(),
            Nm {
                resolver: Arc::new(RelatedResolver::<E, T> { target: other.entity, _pd: PhantomData }),
                junction,
                source_col,
                target_col,
            },
        );
        self.relations.push(MetaRelation {
            name: other.slug.clone(),
            target: other.table.clone(),
            cardinality: Cardinality::ToMany,
            owns_fk: false,
            fk_column: None,
            read_only: false,
            hidden: false,
            label: None,
            description: None,
            from_col: self.pk.first().cloned().unwrap_or_default(),
            to_col: String::new(),
            is_nm: true,
        });
        self
    }

    fn columns(&self) -> Vec<Column> {
        let mut out = Vec::new();
        let mut emitted: Vec<String> = Vec::new();
        for f in &self.fields {
            if let Some(r) = self
                .relations
                .iter()
                .find(|r| r.owns_fk && r.fk_column.as_deref() == Some(f.name.as_str()))
            {
                out.push(relation_column(r));
                emitted.push(r.name.clone());
            } else if !f.hidden {
                out.push(Column::Field {
                    name: f.name.clone(),
                    logical_type: f.logical_type,
                    read_only: f.read_only,
                    write_only: f.write_only,
                    nullable: f.nullable,
                    // The schema facts, narrowed by the app's config: a field it has made unwritable
                    // can't be required of a caller. Kept here rather than in `MetaField::required` so
                    // flipping `read_only` after `MetaModel::new` does the right thing.
                    required: f.required && !f.read_only && !f.hidden,
                    options: f.options.clone(),
                    label: f.label.clone(),
                    description: f.description.clone(),
                    default: f.default.clone(),
                    display: f.display,
                });
            }
        }
        for r in &self.relations {
            if !r.hidden && !emitted.contains(&r.name) {
                out.push(relation_column(r));
            }
        }
        out
    }

    fn read_scalars(&self, full: &Value) -> Map<String, Value> {
        let mut m = Map::new();
        for f in &self.fields {
            if f.hidden || f.write_only {
                continue;
            }
            let v = full.get(&f.name).cloned().unwrap_or(Value::Null);
            let v = match &f.on_read {
                Some(t) => t(&v),
                None => v,
            };
            m.insert(f.name.clone(), v);
        }
        m
    }

    /// Coerce + validate writable scalar fields; split out relation ops (to-one FK / N:M ids).
    #[allow(clippy::type_complexity)]
    fn prepare_write(
        &self,
        obj: &Map<String, Value>,
        is_create: bool,
    ) -> Result<(Vec<(String, Value)>, Vec<(String, Value)>, Vec<(String, Vec<Value>)>)> {
        let mut errs = ValidationErrors::new();
        let (mut scalars, mut to_one, mut nm_ops) = (Vec::new(), Vec::new(), Vec::new());

        for f in &self.fields {
            if f.hidden || f.read_only || (is_create && f.is_pk) {
                continue;
            }
            // A field the caller *can* write and must: absent on create is a client error (422 with the
            // field named), where letting it through produced a 500 carrying the database's own message.
            // Skipped for update, where an absent field means "leave it alone" — requiring it there would
            // make partial updates impossible.
            let Some(raw) = obj.get(&f.name) else {
                if is_create && f.required {
                    errs.field(&f.name, "required");
                }
                continue;
            };
            match coerce(f.logical_type, raw).map(|v| f.normalize_blank(v)) {
                Err(e) => errs.field(&f.name, e),
                Ok(norm) => {
                    // An explicit `null` for a NOT NULL column is the same client error, and it is one on
                    // *update* too — nulling such a column can never succeed.
                    if f.required && norm.is_null() {
                        errs.field(&f.name, "required");
                        continue;
                    }
                    // A closed set is checked before the app's own validator, so a predicate never sees a
                    // value the column can't hold. Without this the database decided — a 500 on a real
                    // enum column, or silently-stored nonsense where the "enum" is a text column.
                    if let Some(e) = f.options_error(&norm) {
                        errs.field(&f.name, e);
                        continue;
                    }
                    if let Some(v) = &f.validate {
                        if let Err(e) = v(&norm) {
                            errs.field(&f.name, e);
                            continue;
                        }
                    }
                    let out = match &f.on_write {
                        Some(t) => t(norm),
                        None => norm,
                    };
                    scalars.push((f.name.clone(), out));
                }
            }
        }

        for r in &self.relations {
            if r.read_only || r.hidden {
                continue;
            }
            let Some(v) = obj.get(&r.name) else { continue };
            if r.owns_fk {
                if let Some(fk) = &r.fk_column {
                    to_one.push((fk.clone(), v.clone()));
                }
            } else if r.is_nm {
                nm_ops.push((r.name.clone(), v.as_array().cloned().unwrap_or_default()));
            }
        }

        if let Some(rv) = &self.validate_row {
            let map: Map<String, Value> = scalars.iter().cloned().collect();
            if let Err(e) = rv(&map) {
                e.fields.into_iter().for_each(|(k, m)| errs.field(k, m));
                e.errors.into_iter().for_each(|m| errs.general(m));
            }
        }

        if errs.is_empty() {
            Ok((scalars, to_one, nm_ops))
        } else {
            Err(Error::Validation(errs))
        }
    }
}

/// A relation's backend-agnostic metadata. `target` is the raw table name here; `SeaAccessor::columns`
/// maps it to the target's slug via the registry.
fn relation_column(r: &MetaRelation) -> Column {
    Column::Relation {
        name: r.name.clone(),
        target: r.target.clone(),
        cardinality: r.cardinality,
        fk_column: r.fk_column.clone(),
        read_only: r.read_only,
        label: r.label.clone(),
        description: r.description.clone(),
    }
}

struct RawRel {
    name: String,
    target: String,
    cardinality: Cardinality,
    owns_fk: bool,
    from_col: String,
    to_col: String,
}

fn introspect_relations<E: EntityTrait>() -> Vec<RawRel> {
    <E::Relation as Iterable>::iter()
        .map(|r| {
            let def = r.def();
            RawRel {
                name: format!("{r:?}").to_lowercase(),
                target: table_ref_name(&def.to_tbl),
                cardinality: match def.rel_type {
                    RelationType::HasOne => Cardinality::ToOne,
                    RelationType::HasMany => Cardinality::ToMany,
                },
                owns_fk: !def.is_owner,
                from_col: first_identity_col(&def.from_col),
                to_col: first_identity_col(&def.to_col),
            }
        })
        .collect()
}

// ---- SeaAccessor: the SeaORM `Accessor` implementation ----

struct SeaAccessor<E: EntityTrait> {
    db: DatabaseConnection,
    model: MetaModel<E>,
    registry: Arc<SeaRegistry>,
}

impl<E> SeaAccessor<E>
where
    E: EntityTrait + Send + Sync,
    E::Model: Serialize + Sync,
    E::ActiveModel: ActiveModelTrait<Entity = E>,
{
    /// Build the query condition from a `ListQuery` (shared by `list` and `delete_many`).
    fn build_condition(&self, q: &ListQuery) -> Result<Condition> {
        let mut cond = Condition::all();
        for (col, pat) in &q.search {
            match col {
                Some(name) => {
                    let c = column::<E>(name)
                        .ok_or_else(|| Error::BadRequest(format!("unknown column: {name}")))?;
                    cond = cond.add(c.contains(pat));
                }
                None => {
                    let mut any = Condition::any();
                    for c in <E::Column as Iterable>::iter() {
                        if logical_type(c.def().get_column_type()).is_text() {
                            any = any.add(c.contains(pat));
                        }
                    }
                    cond = cond.add(any);
                }
            }
        }
        for (name, val) in &q.eq {
            let c = column::<E>(name)
                .ok_or_else(|| Error::BadRequest(format!("unknown column: {name}")))?;
            cond = cond.add(c.eq(str_to_db(c.def().get_column_type(), val)));
        }
        if !q.pk_in.is_empty() {
            let name = self.model.pk.first().cloned().unwrap_or_default();
            let c = column::<E>(&name)
                .ok_or_else(|| Error::BadRequest(format!("unknown column: {name}")))?;
            let def = c.def();
            let vals: Vec<DbValue> =
                q.pk_in.iter().map(|v| str_to_db(def.get_column_type(), v)).collect();
            cond = cond.add(c.is_in(vals));
        }
        Ok(cond)
    }

    /// Turn raw model rows into listing items, finishing each row unless `terse`.
    async fn rows_to_items(&self, rows: &[E::Model], terse: bool) -> Result<Vec<RowItem>> {
        let pk_col = self.model.pk.first().cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(rows.len());
        for m in rows {
            let raw = serde_json::to_value(m).unwrap();
            let id = raw.get(&pk_col).cloned().unwrap_or(Value::Null);
            let label = (self.model.row_label)(&raw);
            let row = if terse { None } else { Some(self.finish(&raw).await?) };
            out.push(RowItem { id, label, row });
        }
        Ok(out)
    }

    /// The finished, ready-to-send row: visible scalars (`on_read` applied) + resolved relations.
    /// Coerce + validate one write body into the pieces a row insert/update needs. Pure: no database, so
    /// a batch can run this for every row before opening a transaction.
    fn prepare(&self, body: &Value, is_create: bool) -> Result<Prepared> {
        let obj = body.as_object().ok_or_else(|| Error::BadRequest("expected a JSON object".into()))?;
        self.model.prepare_write(obj, is_create)
    }

    async fn finish(&self, raw: &Value) -> Result<Value> {
        let mut out = self.model.read_scalars(raw);
        for r in &self.model.relations {
            if r.hidden {
                continue;
            }
            out.insert(r.name.clone(), self.resolve(r, raw).await?);
        }
        Ok(Value::Object(out))
    }

    /// Resolve one relation of a raw row into a link (to-one) or array of links (to-many / N:M).
    async fn resolve(&self, r: &MetaRelation, raw: &Value) -> Result<Value> {
        if r.is_nm {
            let source_pk = pk_string(&self.model.pk, raw);
            let rows = self.nm_targets(&r.name, &source_pk).await?;
            let target = self.registry.by_table(&r.target);
            return Ok(Value::Array(rows.iter().map(|tr| link(target.as_deref(), tr)).collect()));
        }
        if r.owns_fk {
            let fk = raw.get(&r.from_col).cloned().unwrap_or(Value::Null);
            if fk.is_null() {
                return Ok(Value::Null);
            }
            let id_str = value_key(&fk);
            if let Some(t) = self.registry.by_table(&r.target) {
                if let Some(trow) = t.get_raw(&id_str).await? {
                    return Ok(link(Some(t.as_ref()), &trow));
                }
            }
            return Ok(json!({ "id": fk, "label": format!("#{id_str}") }));
        }
        // inverse (has_many / has_one): target rows where to_col == this row's from_col value.
        let empty = if r.cardinality == Cardinality::ToOne {
            Value::Null
        } else {
            Value::Array(vec![])
        };
        let key = raw.get(&r.from_col).cloned().unwrap_or(Value::Null);
        let (Some(t), false) = (self.registry.by_table(&r.target), key.is_null()) else {
            return Ok(empty);
        };
        let links: Vec<Value> =
            t.list_by(&r.to_col, &key).await?.iter().map(|tr| link(Some(t.as_ref()), tr)).collect();
        if r.cardinality == Cardinality::ToOne {
            Ok(links.into_iter().next().unwrap_or(Value::Null))
        } else {
            Ok(Value::Array(links))
        }
    }

    async fn nm_targets(&self, rel: &str, source_pk: &str) -> Result<Vec<Value>> {
        match self.model.nm.get(rel) {
            Some(nm) => nm.resolver.read(&self.db, source_pk).await,
            None => Ok(vec![]),
        }
    }

    async fn write_nm<C: ConnectionTrait>(&self, db: &C, rel: &str, source_pk: &str, ids: &[Value]) -> Result<()> {
        let Some(nm) = self.model.nm.get(rel) else {
            return Ok(());
        };
        let backend = db.get_database_backend();
        let src = key_to_db(&json_key(source_pk));
        let del = Query::delete()
            .from_table(Alias::new(&nm.junction))
            .and_where(Expr::col(Alias::new(&nm.source_col)).eq(src.clone()))
            .to_owned();
        db.execute(backend.build(&del)).await?;
        for id in ids {
            let ins = Query::insert()
                .into_table(Alias::new(&nm.junction))
                .columns([Alias::new(&nm.source_col), Alias::new(&nm.target_col)])
                .values_panic([src.clone().into(), key_to_db(id).into()])
                .to_owned();
            db.execute(backend.build(&ins)).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl<E> SeaRow for SeaAccessor<E>
where
    E: EntityTrait + Send + Sync,
    E::Model: Serialize + Sync,
    E::ActiveModel: ActiveModelTrait<Entity = E>,
{
    fn slug(&self) -> &str {
        &self.model.slug
    }
    fn pk_col(&self) -> String {
        self.model.pk.first().cloned().unwrap_or_else(|| "id".into())
    }
    fn label_of(&self, raw: &Value) -> String {
        (self.model.row_label)(raw)
    }
    async fn get_raw(&self, pk: &str) -> Result<Option<Value>> {
        let model = E::find().filter(pk_condition::<E>(pk)?).one(&self.db).await?;
        Ok(model.map(|m| serde_json::to_value(m).unwrap()))
    }
    async fn list_by(&self, col: &str, val: &Value) -> Result<Vec<Value>> {
        let c = column::<E>(col).ok_or_else(|| Error::BadRequest(format!("unknown column: {col}")))?;
        let dbv = json_to_db(c.def().get_column_type(), val);
        let rows = E::find().filter(c.eq(dbv)).limit(100).all(&self.db).await?;
        Ok(rows.iter().map(|m| serde_json::to_value(m).unwrap()).collect())
    }
}

/// One write body, coerced and validated into the pieces a row insert/update needs: scalar columns,
/// to-one foreign keys, and N:M link sets.
type Prepared = (Vec<(String, Value)>, Vec<(String, Value)>, Vec<(String, Vec<Value>)>);

/// The write helpers, which need the same bounds as the `Accessor` impl (a default `ActiveModel` to insert
/// into, and a `Model` that can become one to update).
impl<E> SeaAccessor<E>
where
    E: EntityTrait + Send + Sync,
    E::Model: Serialize + Sync + IntoActiveModel<E::ActiveModel>,
    E::ActiveModel: ActiveModelTrait<Entity = E> + Default + Send + Sync,
{
    /// Insert a prepared row (and its N:M links) on `txn`, returning the **raw** stored row. Relations are
    /// not resolved here: that reads through the pool, which would need a second connection while `txn`
    /// holds the first — a deadlock on a single-connection pool. Callers that want the finished view call
    /// [`finish`](Self::finish) after committing.
    async fn insert_prepared(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        prepared: Prepared,
    ) -> Result<Value> {
        let (scalars, to_one, nm_ops) = prepared;
        let mut am = <E::ActiveModel as Default>::default();
        set_columns::<E>(&mut am, &scalars);
        set_columns::<E>(&mut am, &to_one);
        let model: E::Model = am.insert(txn).await?;
        let full = serde_json::to_value(&model).unwrap();
        let pk = pk_string(&self.model.pk, &full);
        for (rel, ids) in &nm_ops {
            self.write_nm(txn, rel, &pk, ids).await?;
        }
        Ok(full)
    }

    /// Update a prepared row on `txn`; `None` when there is no such row. Raw, as
    /// [`insert_prepared`](Self::insert_prepared).
    async fn update_prepared(
        &self,
        txn: &sea_orm::DatabaseTransaction,
        pk: &str,
        prepared: Prepared,
    ) -> Result<Option<Value>> {
        let (scalars, to_one, nm_ops) = prepared;
        let Some(model) = E::find().filter(pk_condition::<E>(pk)?).one(txn).await? else {
            return Ok(None);
        };
        let mut am = model.into_active_model();
        set_columns::<E>(&mut am, &scalars);
        set_columns::<E>(&mut am, &to_one);
        let model: E::Model = am.update(txn).await?;
        let full = serde_json::to_value(&model).unwrap();
        let pks = pk_string(&self.model.pk, &full);
        for (rel, ids) in &nm_ops {
            self.write_nm(txn, rel, &pks, ids).await?;
        }
        Ok(Some(full))
    }

}

#[async_trait]
impl<E> Accessor for SeaAccessor<E>
where
    E: EntityTrait + Send + Sync,
    E::Model: Serialize + Sync + IntoActiveModel<E::ActiveModel>,
    E::ActiveModel: ActiveModelTrait<Entity = E> + Default + Send + Sync,
{
    fn slug(&self) -> &str {
        &self.model.slug
    }
    fn pk(&self) -> String {
        self.model.pk.first().cloned().unwrap_or_else(|| "id".into())
    }
    fn columns(&self) -> Vec<Column> {
        // Map each relation's target table → the target's slug (the engine wants slugs, not tables).
        self.model
            .columns()
            .into_iter()
            .map(|c| match c {
                Column::Relation {
                    name,
                    target,
                    cardinality,
                    fk_column,
                    read_only,
                    label,
                    description,
                } => Column::Relation {
                    target: self.registry.slug_for(&target).unwrap_or(target),
                    name,
                    cardinality,
                    fk_column,
                    read_only,
                    label,
                    description,
                },
                other => other,
            })
            .collect()
    }

    async fn list(&self, q: &ListQuery, terse: bool) -> Result<Page> {
        let mut sel = E::find().filter(self.build_condition(q)?);
        for (name, desc) in &q.sort {
            let c = column::<E>(name)
                .ok_or_else(|| Error::BadRequest(format!("unknown column: {name}")))?;
            sel = sel.order_by(c, if *desc { Order::Desc } else { Order::Asc });
        }
        if q.all {
            let rows = sel.all(&self.db).await?;
            let total = rows.len() as u64;
            let data = self.rows_to_items(&rows, terse).await?;
            return Ok(Page { total, page: 1, per_page: total, data });
        }
        let per_page = if q.per_page == 0 { 25 } else { q.per_page };
        let page = if q.page == 0 { 1 } else { q.page };
        let paginator = sel.paginate(&self.db, per_page);
        let total = paginator.num_items().await?;
        let rows = paginator.fetch_page(page - 1).await?;
        let data = self.rows_to_items(&rows, terse).await?;
        Ok(Page { total, page, per_page, data })
    }

    async fn get(&self, pk: &str) -> Result<Option<Value>> {
        match E::find().filter(pk_condition::<E>(pk)?).one(&self.db).await? {
            Some(m) => Ok(Some(self.finish(&serde_json::to_value(m).unwrap()).await?)),
            None => Ok(None),
        }
    }

    async fn create(&self, body: &Value) -> Result<Value> {
        let prepared = self.prepare(body, true)?;
        let txn = self.db.begin().await?;
        let full = self.insert_prepared(&txn, prepared).await?;
        txn.commit().await?;
        self.finish(&full).await
    }

    async fn update(&self, pk: &str, body: &Value) -> Result<Option<Value>> {
        let prepared = self.prepare(body, false)?;
        let txn = self.db.begin().await?;
        let Some(full) = self.update_prepared(&txn, pk, prepared).await? else {
            return Ok(None);
        };
        txn.commit().await?;
        Ok(Some(self.finish(&full).await?))
    }

    /// One transaction for the whole batch — see [`Accessor::write_batch`] for why this can't be a loop
    /// over `create`.
    async fn write_batch(&self, rows: Vec<(Option<String>, Value)>) -> Result<BatchApplied> {
        // Phase 1, **before** anything is written: validate every row and collect *all* the complaints.
        // A spreadsheet with four bad cells should be reported in one pass, not one error per re-upload —
        // and this is also what keeps the transaction below short.
        let mut prepared = Vec::with_capacity(rows.len());
        let mut rejected = Vec::new();
        for (i, (pk, body)) in rows.iter().enumerate() {
            match self.prepare(body, pk.is_none()) {
                Ok(p) => prepared.push((pk.clone(), p)),
                Err(e) => rejected.push((i, e)),
            }
        }
        if !rejected.is_empty() {
            return Err(Error::BatchRejected(rejected));
        }

        // Phase 2: apply them all, or none. A database-level failure (a unique violation, a foreign key)
        // can only be found by trying, so this aborts at the first one — dropping the transaction without
        // committing rolls back everything before it.
        let txn = self.db.begin().await?;
        let mut applied = BatchApplied::default();
        for (i, (pk, p)) in prepared.into_iter().enumerate() {
            let outcome = match &pk {
                Some(pk) => self.update_prepared(&txn, pk, p).await.map(|o| o.map(|_| false)),
                None => self.insert_prepared(&txn, p).await.map(|_| Some(true)),
            };
            match outcome {
                Ok(Some(true)) => applied.created += 1,
                Ok(Some(false)) => applied.updated += 1,
                Ok(None) => {
                    return Err(Error::BatchRejected(vec![(i, Error::NotFound)]))
                }
                Err(e) => return Err(Error::BatchRejected(vec![(i, e)])),
            }
        }
        txn.commit().await?;
        Ok(applied)
    }

    async fn delete(&self, pk: &str) -> Result<Option<Value>> {
        // Snapshot the finished view *before* the transaction: `finish` resolves relations (a to-one
        // sibling or an N:M target reads via the pool), and doing that while a write transaction holds
        // a connection would need a second one — deadlocking a single-connection pool (e.g. in-memory
        // SQLite). Relations still exist here since nothing's been deleted yet.
        let Some(model) = E::find().filter(pk_condition::<E>(pk)?).one(&self.db).await? else {
            return Ok(None);
        };
        let raw = serde_json::to_value(&model).unwrap();
        let finished = self.finish(&raw).await?;

        // Then delete atomically: clear N:M junction rows, then the row itself.
        let txn = self.db.begin().await?;
        let backend = txn.get_database_backend();
        let src = key_to_db(&json_key(pk));
        for nm in self.model.nm.values() {
            let del = Query::delete()
                .from_table(Alias::new(&nm.junction))
                .and_where(Expr::col(Alias::new(&nm.source_col)).eq(src.clone()))
                .to_owned();
            txn.execute(backend.build(&del)).await?;
        }
        let res = E::delete_many().filter(pk_condition::<E>(pk)?).exec(&txn).await?;
        txn.commit().await?;
        if res.rows_affected == 0 {
            return Ok(None); // deleted concurrently between the snapshot and the transaction
        }
        Ok(Some(finished))
    }

    async fn delete_many(&self, q: &ListQuery) -> Result<u64> {
        let pk_c = column::<E>(&self.pk())
            .ok_or_else(|| Error::Backend("no primary-key column".into()))?;
        let txn = self.db.begin().await?;
        let backend = txn.get_database_backend();
        // Clear N:M junction rows for the matching source rows (subquery) BEFORE deleting parents.
        for nm in self.model.nm.values() {
            let sub = E::find()
                .filter(self.build_condition(q)?)
                .select_only()
                .column(pk_c)
                .into_query();
            let del = Query::delete()
                .from_table(Alias::new(&nm.junction))
                .and_where(Expr::col(Alias::new(&nm.source_col)).in_subquery(sub))
                .to_owned();
            txn.execute(backend.build(&del)).await?;
        }
        let res = E::delete_many().filter(self.build_condition(q)?).exec(&txn).await?;
        txn.commit().await?;
        Ok(res.rows_affected)
    }
}

fn set_columns<E: EntityTrait>(am: &mut E::ActiveModel, cols: &[(String, Value)])
where
    E::ActiveModel: ActiveModelTrait<Entity = E>,
{
    for (name, jv) in cols {
        if let Some(c) = column::<E>(name) {
            am.set(c, json_to_db(c.def().get_column_type(), jv));
        }
    }
}

fn json_key(s: &str) -> Value {
    match s.parse::<i64>() {
        Ok(n) => json!(n),
        Err(_) => json!(s),
    }
}

// ---- Crud facade ----

pub struct Crud {
    engine: Engine,
    db: DatabaseConnection,
    registry: Arc<SeaRegistry>,
}

impl Crud {
    /// `base_path` is the mount prefix (e.g. `"/api/v1"`; `""` for root).
    pub fn new(db: DatabaseConnection, base_path: impl Into<String>) -> Self {
        Self {
            engine: Engine::new(base_path),
            db,
            registry: Arc::new(SeaRegistry::default()),
        }
    }

    /// Register a model behind an authorization gate. Pass [`Open`](crate::authz::Open) for an
    /// ungated endpoint, or a gate built from your [`Auth`](crate::auth::Auth) — e.g.
    /// `crud.register(post, UserReadGroupWrite::new(&auth, ["admin"]))`. Share one gate across models
    /// by passing an `Arc<dyn Authz>` (it implements the trait). Each gate is handed the request,
    /// resolves the identity itself, and returns a [`Decision`](crate::authz::Decision) → the handler
    /// maps it to `200`/`401`/`403`.
    pub fn register<E, G>(&mut self, model: MetaModel<E>, gate: G) -> &mut Self
    where
        E: EntityTrait + Send + Sync,
        E::Model: Serialize + Sync + IntoActiveModel<E::ActiveModel>,
        E::ActiveModel: ActiveModelTrait<Entity = E> + Default + Send + Sync,
        G: crate::authz::Authz + 'static,
    {
        let table = model.table.clone();
        let acc = Arc::new(SeaAccessor {
            db: self.db.clone(),
            model,
            registry: self.registry.clone(),
        });
        // Same instance serves two roles: a sibling row source (weak, for relation resolution) and
        // the engine's accessor (strong, keeps it alive).
        let as_row: Arc<dyn SeaRow> = acc.clone();
        self.registry.insert(&table, Arc::downgrade(&as_row));
        self.engine.add(acc, Arc::new(gate));
        self
    }

    /// Register an audit sink fired after each committed write (create/update/delete/bulk-delete)
    /// through this engine — see [`crate::observe`]. Share one `Arc` with `Auth::on_write` to capture
    /// both the auto-CRUD and auth surfaces in one place.
    pub fn on_write(&mut self, observer: Arc<dyn crate::observe::WriteObserver>) -> &mut Self {
        self.engine.set_observer(observer);
        self
    }

    /// Require a valid **CSRF token** on every write through this API — the double-submit token from
    /// [`crate::csrf`]. Pass the app's checker so the API and the `auth` login/profile forms share one
    /// token cookie:
    ///
    /// ```ignore
    /// crud.csrf(auth.csrf());   // writes now need the X-CSRF-Token header
    /// ```
    ///
    /// Writes then answer `403 {"error":"csrf token missing or invalid"}` unless the request echoes the
    /// cookie in `X-CSRF-Token` (or carries an `Authorization` header, which is exempt). The
    /// `crud::ui` tables add the header automatically. Off by default — a browserless API that
    /// authenticates some other way needs no token.
    #[cfg(feature = "csrf")]
    pub fn csrf(&mut self, csrf: crate::csrf::Csrf) -> &mut Self {
        self.engine.set_csrf(csrf);
        self
    }

    /// The underlying backend-agnostic engine (for direct use or a custom transport).
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
    pub fn into_engine(self) -> Engine {
        self.engine
    }

    #[cfg(feature = "axum")]
    pub fn into_router(self) -> axum::Router {
        Arc::new(self.engine).router()
    }
}

/// A tiny entity for the metadata tests: one NOT NULL and one nullable text column, plus a nullable
/// int, so introspection has something to read `ColumnDef::is_null()` off.
#[cfg(test)]
mod nullable_tests {
    use super::*;

    mod thing {
        use sea_orm::entity::prelude::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
        #[sea_orm(table_name = "thing")]
        pub struct Model {
            #[sea_orm(primary_key)]
            pub id: i32,
            pub name: String,             // NOT NULL
            pub nickname: Option<String>, // nullable
            pub note: Option<String>,     // nullable
            pub rank: Option<i32>,        // nullable int
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    /// The metadata a frontend/OpenAPI consumer sees for each column.
    fn nullability(mm: &MetaModel<thing::Entity>) -> Vec<(String, bool)> {
        mm.columns()
            .into_iter()
            .filter_map(|c| match c {
                Column::Field { name, nullable, .. } => Some((name, nullable)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn nullability_is_read_from_the_entity() {
        let mm = MetaModel::new(thing::Entity);
        assert_eq!(
            nullability(&mm),
            vec![
                ("id".to_string(), false),
                ("name".to_string(), false),
                ("nickname".to_string(), true),
                ("note".to_string(), true),
                ("rank".to_string(), true),
            ]
        );
    }

    /// Coerce + normalize one write body, returning the scalars that would be written.
    fn scalars(mm: &MetaModel<thing::Entity>, body: Value) -> Vec<(String, Value)> {
        let obj = body.as_object().unwrap().clone();
        let (scalars, _, _) = mm.prepare_write(&obj, true).expect("no validation errors");
        scalars
    }

    /// The validation errors a write would produce, for the cases that must not reach the database.
    fn write_errors(mm: &MetaModel<thing::Entity>, body: Value, is_create: bool) -> ValidationErrors {
        let obj = body.as_object().unwrap().clone();
        match mm.prepare_write(&obj, is_create) {
            Err(Error::Validation(v)) => v,
            other => panic!("expected validation errors, got {:?}", other.map(|_| "ok")),
        }
    }

    /// An entity with a **real** enum column, so introspection has variants to find. `db_type = "Enum"`
    /// is what makes `ColumnDef::get_column_type()` report `ColumnType::Enum`; a `DeriveActiveEnum` with
    /// `db_type = "String"` is a text column as far as the schema knows, which is the case the app has to
    /// declare `options` for by hand (tested separately below).
    mod enum_thing {
        use sea_orm::entity::prelude::*;

        #[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, serde::Serialize, serde::Deserialize)]
        #[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "post_status")]
        pub enum Status {
            #[sea_orm(string_value = "draft")]
            Draft,
            #[sea_orm(string_value = "review")]
            Review,
            #[sea_orm(string_value = "published")]
            Published,
        }

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
        #[sea_orm(table_name = "enum_thing")]
        pub struct Model {
            #[sea_orm(primary_key)]
            pub id: i32,
            pub status: Status,          // NOT NULL enum
            pub mood: Option<Status>,    // nullable enum
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    #[test]
    fn enum_variants_are_introspected_and_published() {
        let mm = MetaModel::new(enum_thing::Entity);
        let opts: Vec<(String, Vec<String>)> =
            mm.fields().map(|f| (f.name.clone(), f.options.clone())).collect();
        assert_eq!(
            opts,
            vec![
                ("id".to_string(), vec![]),
                ("status".to_string(), vec!["draft".into(), "review".into(), "published".into()]),
                ("mood".to_string(), vec!["draft".into(), "review".into(), "published".into()]),
            ],
            "declaration order, for both the NOT NULL and the nullable column"
        );
        // …and they reach the published shape, which is what the form and OpenAPI read.
        let published: Vec<Vec<String>> = mm
            .columns()
            .iter()
            .filter_map(|c| match c {
                Column::Field { name, options, .. } if name == "status" => Some(options.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(published, vec![vec!["draft".to_string(), "review".into(), "published".into()]]);
    }

    #[test]
    fn a_value_outside_the_set_is_refused() {
        let mm = MetaModel::new(enum_thing::Entity);
        let write = |body: Value| {
            let obj = body.as_object().unwrap().clone();
            mm.prepare_write(&obj, true)
        };

        // A variant goes through.
        assert!(write(serde_json::json!({ "status": "review" })).is_ok());
        // Anything else is a field error rather than whatever the database would have said — including a
        // near miss, a wrong case (database enums are case-sensitive), and a non-string.
        for bad in [
            serde_json::json!({ "status": "reviewed" }),
            serde_json::json!({ "status": "Review" }),
            serde_json::json!({ "status": "" }),
            serde_json::json!({ "status": 1 }),
        ] {
            match write(bad.clone()) {
                Err(Error::Validation(v)) => assert_eq!(
                    v.fields.get("status").map(String::as_str),
                    Some("must be one of: draft, review, published"),
                    "{bad}"
                ),
                other => panic!("{bad} should have been refused, got {:?}", other.map(|_| "ok")),
            }
        }

        // A nullable enum still accepts null — absence is `required`'s business, not the set's.
        assert!(write(serde_json::json!({ "status": "draft", "mood": null })).is_ok());
    }

    #[test]
    fn options_can_be_declared_by_hand_on_a_text_column() {
        // The common SQLite shape: a `DeriveActiveEnum` with `db_type = "String"` is just text, so there
        // is nothing to introspect and the app supplies the set. The check and the widget key off the
        // list, not off the logical type.
        let mut mm = MetaModel::new(thing::Entity);
        assert!(mm.field("name").options.is_empty(), "a text column has no set by default");
        mm.field("name").options = vec!["alpha".into(), "beta".into()];

        let ok = serde_json::json!({ "name": "beta" }).as_object().unwrap().clone();
        assert!(mm.prepare_write(&ok, true).is_ok());
        let bad = serde_json::json!({ "name": "gamma" }).as_object().unwrap().clone();
        let errs = write_errors(&mm, serde_json::json!({ "name": "gamma" }), true);
        assert_eq!(errs.fields.get("name").map(String::as_str), Some("must be one of: alpha, beta"));
        let _ = bad;
    }

    /// An entity whose `NOT NULL` timestamp is filled by a **hook**, not by the database and not by the
    /// caller — the `auth_user.created_at` shape, which is the configuration `required` interacts with
    /// most awkwardly.
    mod stamped {
        use sea_orm::entity::prelude::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
        #[sea_orm(table_name = "stamped")]
        pub struct Model {
            #[sea_orm(primary_key)]
            pub id: i32,
            pub title: String,
            /// NOT NULL, no database default, never sent by a client.
            pub created_at: i64,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        #[async_trait::async_trait]
        impl ActiveModelBehavior for ActiveModel {
            async fn before_save<C: ConnectionTrait>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr> {
                if insert {
                    self.created_at = sea_orm::ActiveValue::Set(1_700_000_000);
                }
                Ok(self)
            }
        }
    }

    #[tokio::test]
    async fn a_hook_stamped_column_is_filled_even_though_the_caller_never_sends_it() {
        use crate::authz::Open;
        use sea_orm::{ConnectionTrait, Database, Schema};

        // The schema says `created_at` is required — NOT NULL, no default, not the key. That is the fact
        // introspection reads, and on its own it would make every create a 422.
        let mut mm = MetaModel::new(stamped::Entity);
        assert!(mm.field("created_at").required, "the raw schema fact");

        // Marking it read-only is what an app must do for a hook-filled column (both examples do), and it
        // is what exempts it: a caller has no way to supply it, so requiring it of them is nonsense.
        mm.field("created_at").read_only = true;
        let published: Vec<bool> = mm
            .columns()
            .iter()
            .filter_map(|c| match c {
                Column::Field { name, required, .. } if name == "created_at" => Some(*required),
                _ => None,
            })
            .collect();
        assert_eq!(published, vec![false], "not required *of the caller*");

        // Now prove the whole chain against a real database: the engine omits the column, the hook fills
        // it during the insert, and the row comes back stamped.
        let db = Database::connect("sqlite::memory:").await.expect("sqlite");
        let schema = Schema::new(db.get_database_backend());
        let stmt = schema.create_table_from_entity(stamped::Entity);
        db.execute(db.get_database_backend().build(&stmt)).await.expect("create table");

        let mut crud = Crud::new(db.clone(), "");
        crud.register(mm, Open);
        let engine = crud.into_engine();
        // A create body with no `created_at` — which is how every real client writes.
        let created = engine
            .create("stamped", &serde_json::json!({ "title": "t" }))
            .await
            .expect("the create must succeed, not 422 and not 500");

        assert_eq!(created.get("title").and_then(|v| v.as_str()), Some("t"));
        assert_eq!(
            created.get("created_at").and_then(|v| v.as_i64()),
            Some(1_700_000_000),
            "the before_save hook stamped it, and the read reflects it"
        );
        let row = stamped::Entity::find().one(&db).await.expect("query").expect("one row");
        assert_eq!(row.created_at, 1_700_000_000, "…and it is what the database holds");

        // The upgrade hazard, asserted: **forget** the `read_only` and the same create is refused, because
        // from the engine's side a hook-filled column is indistinguishable from one nothing fills. This is
        // the one item in the 0.2.0 notes that can bite an app silently, so it gets a test rather than only
        // a paragraph.
        let bare = MetaModel::new(stamped::Entity);
        let obj = serde_json::json!({ "title": "t" }).as_object().unwrap().clone();
        match bare.prepare_write(&obj, true) {
            Err(Error::Validation(v)) => assert_eq!(
                v.fields.get("created_at").map(String::as_str),
                Some("required"),
                "mark a hook-filled column read_only, or it is required of the caller"
            ),
            other => panic!("expected a required error, got {:?}", other.map(|_| "ok")),
        }
    }

    /// Build a live engine over an in-memory SQLite holding the `stamped` table.
    async fn stamped_engine() -> (sea_orm::DatabaseConnection, Engine) {
        use crate::authz::Open;
        use sea_orm::{ConnectionTrait, Database, Schema};
        let db = Database::connect("sqlite::memory:").await.expect("sqlite");
        let schema = Schema::new(db.get_database_backend());
        let stmt = schema.create_table_from_entity(stamped::Entity);
        db.execute(db.get_database_backend().build(&stmt)).await.expect("create table");
        let mut mm = MetaModel::new(stamped::Entity);
        mm.field("created_at").read_only = true;
        let mut crud = Crud::new(db.clone(), "");
        crud.register(mm, Open);
        (db, crud.into_engine())
    }

    async fn stamped_count(db: &sea_orm::DatabaseConnection) -> usize {
        stamped::Entity::find().all(db).await.expect("query").len()
    }

    #[tokio::test]
    async fn a_batch_write_applies_every_row_or_none_of_them() {
        let (db, engine) = stamped_engine().await;
        let row = |t: &str| (None, serde_json::json!({ "title": t }));

        // All good → all applied.
        let applied = engine
            .write_batch("stamped", vec![row("a"), row("b"), row("c")])
            .await
            .expect("all valid");
        assert_eq!((applied.created, applied.updated), (3, 0));
        assert_eq!(stamped_count(&db).await, 3);

        // One bad row anywhere in the file → **nothing** applied, not even the rows before it. This is the
        // whole point: a file that fails on line 40 must not half-import a spreadsheet.
        let bad = vec![row("d"), (None, serde_json::json!({})), row("e")];
        match engine.write_batch("stamped", bad).await {
            Err(Error::BatchRejected(rows)) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].0, 1, "the offending row is named by index");
                assert_eq!(rows[0].1.one_line(), "title: required");
            }
            other => panic!("expected a rejection, got {:?}", other.map(|_| "ok")),
        }
        assert_eq!(stamped_count(&db).await, 3, "the good rows around it were rolled back");

        // Every invalid row is reported in one pass, so a spreadsheet is fixed once rather than per upload.
        let many_bad =
            vec![(None, serde_json::json!({})), row("f"), (None, serde_json::json!({ "title": null }))];
        match engine.write_batch("stamped", many_bad).await {
            Err(Error::BatchRejected(rows)) => {
                assert_eq!(rows.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 2]);
            }
            other => panic!("expected two rejections, got {:?}", other.map(|_| "ok")),
        }
        assert_eq!(stamped_count(&db).await, 3);
    }

    #[tokio::test]
    async fn a_csv_import_is_all_or_nothing() {
        // The same guarantee through the CSV surface, which is where it matters to a user.
        let (db, engine) = stamped_engine().await;

        let good = "title\nalpha\nbeta\n";
        let report = crate::crud::csv_io::import(&engine, "stamped", good).await.expect("import");
        assert_eq!((report.created, report.updated, report.failed), (2, 0, 0));
        assert_eq!(stamped_count(&db).await, 2);

        // Now a file whose *second* data line updates a row that doesn't exist. The first line is a
        // perfectly good update — and it must be rolled back, which is the guarantee that matters and the
        // one a per-row loop cannot give.
        let before = stamped::Entity::find().one(&db).await.unwrap().unwrap();
        assert_eq!(before.title, "alpha");
        let bad = "id,title\n1,ALPHA\n999,ghost\n";
        let report = crate::crud::csv_io::import(&engine, "stamped", bad).await.expect("import ran");
        assert_eq!((report.created, report.updated), (0, 0), "nothing applied");
        assert_eq!(report.failed, 1);
        assert_eq!(report.errors[0].row, 3, "1-based line, header counted");
        assert_eq!(report.errors[0].message, "not found");
        assert_eq!(stamped_count(&db).await, 2, "no rows added");
        assert_eq!(
            stamped::Entity::find().one(&db).await.unwrap().unwrap().title,
            "alpha",
            "the valid update on the line before was rolled back"
        );
    }

    #[test]
    fn a_required_field_is_introspected_from_the_schema() {
        let mm = MetaModel::new(thing::Entity);
        // NOT NULL with no default → required. Nullable → not. The primary key → not: the database
        // assigns it, and it is read-only anyway.
        let flags: Vec<(String, bool)> =
            mm.fields().map(|f| (f.name.clone(), f.required)).collect();
        assert_eq!(
            flags,
            vec![
                ("id".to_string(), false),
                ("name".to_string(), true),
                ("nickname".to_string(), false),
                ("note".to_string(), false),
                ("rank".to_string(), false),
            ]
        );
    }

    #[test]
    fn a_missing_required_field_is_a_field_error_not_a_database_crash() {
        // The point of the whole feature: omitting `name` used to reach the database, which rejected it,
        // which surfaced as a 500 carrying the database's own message. Now it is a 422 naming the field —
        // which the admin form renders inline, and which doesn't leak the schema.
        let mm = MetaModel::new(thing::Entity);
        let errs = write_errors(&mm, serde_json::json!({ "nickname": "n" }), true);
        assert_eq!(errs.fields.get("name").map(String::as_str), Some("required"));

        // An explicit `null` is the same client error — and it is one on **update** too, where nulling a
        // NOT NULL column can never succeed.
        for is_create in [true, false] {
            let errs = write_errors(&mm, serde_json::json!({ "name": null }), is_create);
            assert_eq!(errs.fields.get("name").map(String::as_str), Some("required"), "create={is_create}");
        }

        // Absent on **update** is fine: that means "leave it alone", and requiring it would make a
        // partial update impossible.
        let patch = serde_json::json!({ "nickname": "n" }).as_object().unwrap().clone();
        assert!(mm.prepare_write(&patch, false).is_ok(), "a PATCH need not resend every column");

        // `required` means *present*, not non-empty: "" still satisfies a NOT NULL text column, as it did
        // before. A `non_empty` validator is how you ask for more.
        let ok = serde_json::json!({ "name": "" }).as_object().unwrap().clone();
        assert!(mm.prepare_write(&ok, true).is_ok(), "blank is a value; use a validator to refuse it");
    }

    #[test]
    fn the_app_can_opt_out_of_requiring_a_field() {
        // Needed when the *database* has a default the entity doesn't declare — SeaORM can't see it, so
        // introspection assumes the column is required.
        let mut mm = MetaModel::new(thing::Entity);
        mm.field("name").required = false;
        let obj = serde_json::json!({ "nickname": "n" }).as_object().unwrap().clone();
        assert!(mm.prepare_write(&obj, true).is_ok(), "opted out");

        // And making a field unwritable exempts it without touching `required` — which is what spares a
        // `created_at` filled by a `before_save` hook.
        let mut mm = MetaModel::new(thing::Entity);
        mm.field("name").read_only = true;
        let obj = serde_json::json!({}).as_object().unwrap().clone();
        assert!(mm.prepare_write(&obj, true).is_ok(), "read-only can't be required of a caller");
        // …and the published flag agrees, so the form doesn't mark a field it can't fill.
        let published: Vec<bool> = mm
            .columns()
            .iter()
            .filter_map(|c| match c {
                Column::Field { name, required, .. } if name == "name" => Some(*required),
                _ => None,
            })
            .collect();
        assert_eq!(published, vec![false]);
    }

    #[test]
    fn a_blank_string_becomes_null_only_where_null_is_possible() {
        let mm = MetaModel::new(thing::Entity);
        let out = scalars(&mm, serde_json::json!({ "name": "", "nickname": "", "note": "  " }));
        assert_eq!(
            out,
            vec![
                // NOT NULL: "" is the only way to say "empty", so it's kept verbatim. This is what
                // keeps `MetaField::password()`'s blank-means-no-password behaviour working.
                ("name".to_string(), Value::String(String::new())),
                // Nullable: a blank input means "nothing here" → SQL NULL, not "".
                ("nickname".to_string(), Value::Null),
                // Only an *empty* string is canonicalized; whitespace is content.
                ("note".to_string(), Value::String("  ".into())),
            ]
        );
    }

    #[test]
    fn values_and_explicit_nulls_pass_through_untouched() {
        let mm = MetaModel::new(thing::Entity);
        let out = scalars(
            &mm,
            serde_json::json!({ "name": "thing", "nickname": "nick", "note": null, "rank": 3 }),
        );
        assert_eq!(
            out,
            vec![
                ("name".to_string(), Value::String("thing".into())),
                ("nickname".to_string(), Value::String("nick".into())),
                ("note".to_string(), Value::Null),
                ("rank".to_string(), Value::from(3)),
            ]
        );
    }

    #[test]
    fn blank_is_null_can_be_switched_off_per_field() {
        // For a column where "" and NULL are meaningfully different to the app.
        let mut mm = MetaModel::new(thing::Entity);
        mm.field("nickname").blank_is_null = false;
        // `name` is NOT NULL, so a create body carries it — this test is about `nickname`.
        let out = scalars(&mm, serde_json::json!({ "name": "t", "nickname": "" }));
        assert_eq!(
            out,
            vec![
                ("name".to_string(), Value::String("t".into())),
                ("nickname".to_string(), Value::String(String::new())),
            ]
        );
    }

    #[test]
    fn a_validator_sees_the_canonical_value() {
        // The normalization runs before `validate`, so a predicate lifted with `validate_str` gets
        // `null` (which it passes — nullability is the column's concern) rather than "".
        let mut mm = MetaModel::new(thing::Entity);
        mm.field("nickname").validate_str(crate::validate::non_empty);
        let out = scalars(&mm, serde_json::json!({ "name": "t", "nickname": "" }));
        assert_eq!(
            out,
            vec![("name".to_string(), Value::String("t".into())), ("nickname".to_string(), Value::Null)],
            "blank was not rejected as empty"
        );
        // …and a real value still goes through the predicate, which still rejects what it should
        // (`non_empty` treats whitespace as empty).
        let ok = serde_json::json!({ "name": "t", "nickname": "nick" }).as_object().unwrap().clone();
        assert!(mm.prepare_write(&ok, true).is_ok());
        let blank = serde_json::json!({ "name": "t", "nickname": "   " }).as_object().unwrap().clone();
        assert!(mm.prepare_write(&blank, true).is_err(), "whitespace-only is still rejected");
    }

    #[test]
    fn the_metadata_json_carries_nullability() {
        let mm = MetaModel::new(thing::Entity);
        let cols = mm.columns();
        let engine_view: Vec<Value> = cols
            .into_iter()
            .filter_map(|c| match c {
                Column::Field { name, nullable, .. } => {
                    Some(serde_json::json!({ "name": name, "nullable": nullable }))
                }
                _ => None,
            })
            .collect();
        assert!(engine_view.iter().any(|c| c["name"] == "nickname" && c["nullable"] == true));
        assert!(engine_view.iter().any(|c| c["name"] == "name" && c["nullable"] == false));
    }
}

#[cfg(all(test, feature = "auth"))]
mod tests {
    use super::*;
    use crate::auth::verify_password;

    fn text_field(name: &str) -> MetaField {
        MetaField {
            name: name.into(),
            logical_type: LogicalType::Text,
            is_pk: false,
            is_fk: false,
            required: true,
            options: Vec::new(),
            nullable: false,
            blank_is_null: true,
            read_only: false,
            write_only: false,
            hidden: false,
            label: None,
            description: None,
            default: None,
            display: None,
            validate: None,
            on_write: None,
            on_read: None,
        }
    }

    #[test]
    fn password_helper_hashes_nonempty_and_disables_login_when_empty() {
        let mut f = text_field("password_hash");
        f.password();

        assert!(f.write_only, "password field must be write-only");
        assert_eq!(f.label.as_deref(), Some("Password"));
        let on_write = f.on_write.as_ref().expect("password() sets on_write");

        // Non-empty plaintext → a verifiable argon2 hash (and the plaintext isn't stored verbatim).
        let hashed = on_write(Value::String("s3cret".into()));
        let hash = hashed.as_str().unwrap();
        assert_ne!(hash, "s3cret");
        assert!(verify_password(hash, "s3cret"));
        assert!(!verify_password(hash, "wrong"));

        // Empty plaintext → empty hash, which no password can verify against (login disabled).
        let empty = on_write(Value::String(String::new()));
        assert_eq!(empty.as_str(), Some(""));
        assert!(!verify_password("", ""));
        assert!(!verify_password("", "anything"));
    }

    #[test]
    fn password_helper_keeps_a_preset_label() {
        let mut f = text_field("secret");
        f.label = Some("Passphrase".into());
        f.password();
        assert_eq!(f.label.as_deref(), Some("Passphrase"));
    }
}
