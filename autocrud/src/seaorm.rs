//! SeaORM backend flavor: introspection + the `MetaModel` builder + an `Accessor` implementation.
//! This is the only module that depends on SeaORM.

use crate::engine::{
    coerce, default_label, slugify, value_key, Accessor, Cardinality, ColumnMeta, Engine, Error,
    ListQuery, LogicalType, Page, Result, RowItem, ValidationErrors,
};
use async_trait::async_trait;
use sea_orm::sea_query::{Alias, DynIden, Expr, Query, TableRef};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ColumnType, Condition, ConnectionTrait, DatabaseConnection,
    DbErr, EntityName, EntityTrait, IdenStatic, Identity, IntoActiveModel, Iterable, ModelTrait,
    Order, PaginatorTrait, PrimaryKeyToColumn, QueryFilter, QueryOrder, QuerySelect, QueryTrait,
    Related, RelationTrait, RelationType, TransactionTrait, Value as DbValue,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use std::sync::{Arc, RwLock, Weak};

impl From<DbErr> for Error {
    fn from(e: DbErr) -> Self {
        Error::Backend(e.to_string())
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
pub struct MetaField {
    // Informational — set by introspection:
    pub name: String,
    pub logical_type: LogicalType,
    pub is_pk: bool,
    pub is_fk: bool,
    // Visibility — you may change these:
    pub read_only: bool,
    pub write_only: bool,
    pub hidden: bool,
    // Presentation — optional:
    pub label: Option<String>,       // display label (defaults to the field name in the UI)
    pub description: Option<String>, // help text shown under the field in forms
    pub default: Option<Value>,      // create-form default value (edit uses the row)
    // Optional user hooks:
    pub validate: Option<Validator>,
    pub on_write: Option<WriteTransform>,
    pub on_read: Option<ReadTransform>,
}

/// A relation of an entity (config the user may tweak via `MetaModel::relation`).
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

/// JSON value → ORM value (for writes), by column type.
fn json_to_db(ct: &ColumnType, v: &Value) -> DbValue {
    if v.is_null() {
        return DbValue::String(None);
    }
    match logical_type(ct) {
        LogicalType::Int => v.as_i64().map(|n| DbValue::from(n as i32)).unwrap_or(DbValue::Int(None)),
        LogicalType::Float => v.as_f64().map(DbValue::from).unwrap_or(DbValue::Double(None)),
        LogicalType::Bool => DbValue::from(v.as_bool().unwrap_or(false)),
        _ => DbValue::from(v.as_str().unwrap_or_default().to_string()),
    }
}

/// String (URL value) → ORM value, by column type.
fn str_to_db(ct: &ColumnType, s: &str) -> DbValue {
    match logical_type(ct) {
        LogicalType::Int => s.parse::<i64>().map(|n| DbValue::from(n as i32)).unwrap_or_else(|_| DbValue::from(s.to_string())),
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
                MetaField {
                    logical_type: logical_type(c.def().get_column_type()),
                    read_only: is_pk,
                    write_only: false,
                    hidden: is_fk,
                    is_pk,
                    is_fk,
                    name,
                    label: None,
                    description: None,
                    default: None,
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

    fn columns(&self) -> Vec<ColumnMeta> {
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
                out.push(ColumnMeta::Field {
                    name: f.name.clone(),
                    logical_type: f.logical_type,
                    read_only: f.read_only,
                    write_only: f.write_only,
                    label: f.label.clone(),
                    description: f.description.clone(),
                    default: f.default.clone(),
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
            let Some(raw) = obj.get(&f.name) else { continue };
            match coerce(f.logical_type, raw) {
                Err(e) => errs.field(&f.name, e),
                Ok(norm) => {
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
fn relation_column(r: &MetaRelation) -> ColumnMeta {
    ColumnMeta::Relation {
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
    fn columns(&self) -> Vec<ColumnMeta> {
        // Map each relation's target table → the target's slug (the engine wants slugs, not tables).
        self.model
            .columns()
            .into_iter()
            .map(|c| match c {
                ColumnMeta::Relation {
                    name,
                    target,
                    cardinality,
                    fk_column,
                    read_only,
                    label,
                    description,
                } => ColumnMeta::Relation {
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
        let obj = body.as_object().ok_or_else(|| Error::BadRequest("expected a JSON object".into()))?;
        let (scalars, to_one, nm_ops) = self.model.prepare_write(obj, true)?;
        let txn = self.db.begin().await?;
        let mut am = <E::ActiveModel as Default>::default();
        set_columns::<E>(&mut am, &scalars);
        set_columns::<E>(&mut am, &to_one);
        let model: E::Model = am.insert(&txn).await?;
        let full = serde_json::to_value(&model).unwrap();
        let pk = pk_string(&self.model.pk, &full);
        for (rel, ids) in &nm_ops {
            self.write_nm(&txn, rel, &pk, ids).await?;
        }
        txn.commit().await?;
        self.finish(&full).await
    }

    async fn update(&self, pk: &str, body: &Value) -> Result<Option<Value>> {
        let obj = body.as_object().ok_or_else(|| Error::BadRequest("expected a JSON object".into()))?;
        let (scalars, to_one, nm_ops) = self.model.prepare_write(obj, false)?;
        let txn = self.db.begin().await?;
        let Some(model) = E::find().filter(pk_condition::<E>(pk)?).one(&txn).await? else {
            return Ok(None);
        };
        let mut am = model.into_active_model();
        set_columns::<E>(&mut am, &scalars);
        set_columns::<E>(&mut am, &to_one);
        let model: E::Model = am.update(&txn).await?;
        let full = serde_json::to_value(&model).unwrap();
        let pks = pk_string(&self.model.pk, &full);
        for (rel, ids) in &nm_ops {
            self.write_nm(&txn, rel, &pks, ids).await?;
        }
        txn.commit().await?;
        Ok(Some(self.finish(&full).await?))
    }

    async fn delete(&self, pk: &str) -> Result<Option<Value>> {
        let txn = self.db.begin().await?;
        let Some(model) = E::find().filter(pk_condition::<E>(pk)?).one(&txn).await? else {
            return Ok(None); // txn dropped -> rolled back
        };
        let raw = serde_json::to_value(&model).unwrap();
        // Snapshot the finished view while relations still exist, then clear junctions + the row.
        let finished = self.finish(&raw).await?;
        let backend = txn.get_database_backend();
        let src = key_to_db(&json_key(pk));
        for nm in self.model.nm.values() {
            let del = Query::delete()
                .from_table(Alias::new(&nm.junction))
                .and_where(Expr::col(Alias::new(&nm.source_col)).eq(src.clone()))
                .to_owned();
            txn.execute(backend.build(&del)).await?;
        }
        E::delete_many().filter(pk_condition::<E>(pk)?).exec(&txn).await?;
        txn.commit().await?;
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

    pub fn register<E>(&mut self, model: MetaModel<E>) -> &mut Self
    where
        E: EntityTrait + Send + Sync,
        E::Model: Serialize + Sync + IntoActiveModel<E::ActiveModel>,
        E::ActiveModel: ActiveModelTrait<Entity = E> + Default + Send + Sync,
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
        self.engine.add(acc);
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
