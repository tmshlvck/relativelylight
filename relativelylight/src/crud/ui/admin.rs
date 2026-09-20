//! [`Admin`] — a side panel over many [`Table`](super::Table)s, rendering one of them per request.

use super::decode::Posted;
use super::state::ViewState;
use super::table::FilterSpec;
use super::{is_filterable, render_err, Outcome, Table};
use crate::crud::engine::{Engine, Error, Result};
use askama::Template;
use http::HeaderMap;
use std::net::IpAddr;

enum NavV {
    Entity { label: String, href: String, active: bool },
    Group(String),
    Separator,
    Link { label: String, href: String },
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminTmpl {
    title: String,
    nav: Vec<NavV>,
    panel: String,
}

/// (`Entity` is much the largest variant, and that is fine: the enum is a per-request configuration
/// list of a dozen items at most, so boxing it would trade a deref in every match for nothing.)
#[allow(clippy::large_enum_variant)]
enum AdminItem<'a> {
    Entity(Table<'a>),
    Group(String),
    Separator,
    Link { label: String, href: String },
}

/// A side panel listing models (plus group headings, separators and custom links) next to **one**
/// model's [`Table`] — the one `?entity=` names, or the first.
///
/// ```ignore
/// let html = Admin::new(&engine)
///     .title("Admin")
///     .group("Content")
///     .entity_with("post", |t| t.per_page(10))
///     .entity("tag")
///     .separator()
///     .link("Log out", "/logout")
///     .render_for(&headers, &state).await?;
/// ```
pub struct Admin<'a> {
    engine: &'a Engine,
    base: Option<String>,
    title: Option<String>,
    items: Vec<AdminItem<'a>>,
    filters: Vec<String>,
}

impl<'a> Admin<'a> {
    pub fn new(engine: &'a Engine) -> Self {
        Self { engine, base: None, title: None, items: Vec::new(), filters: Vec::new() }
    }

    /// Address each entity by **path** — `/admin/post`, `/admin/tag` — instead of by the default
    /// `?entity=post` on one page.
    ///
    /// ```ignore
    /// // .route("/admin/{entity}", get(show).post(save))
    /// let mut state = ViewState::from_uri(&uri);
    /// state.entity = Some(entity);                    // the path decides, not the query
    /// Admin::new(&engine).base("/admin").entity("post")./* … */render_for(&headers, &state).await
    /// ```
    ///
    /// Only the side panel's links change: everything inside a table is relative (`?page=2`,
    /// `?edit=7`) and so resolves against whichever path the panel is being served from, and a
    /// write still redirects to the list it came from. Filters that travel ride along as the
    /// query, so a nav link reads `/admin/tag?filter[zone]=3`.
    ///
    /// Worth it for deep links: `/admin/post?edit=7` says what it is where `?entity=post&edit=7`
    /// needs reading twice. It costs one path parameter in your route, and no extra handler.
    pub fn base(mut self, path: impl Into<String>) -> Self {
        self.base = Some(path.into());
        self
    }

    /// Heading above the side panel.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// One filter control offered to **every** listed table that has a column or to-one relation of
    /// that name; tables without one are unaffected.
    ///
    /// This is the shape that matters when an admin lists many tables of the same kind — fifteen
    /// per-type DNS record tables, say. An operator works inside one zone at a time, so they pick it
    /// once and it follows them from table to table, because every nav link carries it. Like
    /// [`Table::fixed_filter`], it narrows a **view** and is not an authorization boundary.
    pub fn filter(mut self, name: impl Into<String>) -> Self {
        self.filters.push(name.into());
        self
    }

    /// Append every registered entity, in registration order, with default `Table` config.
    pub fn entities(mut self) -> Self {
        for slug in self.engine.tables() {
            self.items.push(AdminItem::Entity(Table::new(self.engine, slug)));
        }
        self
    }
    /// Append one entity with default `Table` config.
    pub fn entity(self, slug: impl Into<String>) -> Self {
        self.entity_with(slug, |t| t)
    }
    /// Append one entity, configuring its `Table`.
    pub fn entity_with(
        mut self,
        slug: impl Into<String>,
        config: impl FnOnce(Table<'a>) -> Table<'a>,
    ) -> Self {
        self.items.push(AdminItem::Entity(config(Table::new(self.engine, slug))));
        self
    }
    /// A group heading in the side panel.
    pub fn group(mut self, name: impl Into<String>) -> Self {
        self.items.push(AdminItem::Group(name.into()));
        self
    }
    /// A horizontal rule in the side panel.
    pub fn separator(mut self) -> Self {
        self.items.push(AdminItem::Separator);
        self
    }
    /// A static link in the side panel.
    pub fn link(mut self, label: impl Into<String>, href: impl Into<String>) -> Self {
        self.items.push(AdminItem::Link { label: label.into(), href: href.into() });
        self
    }

    /// Render the panel for this request: the nav, plus the active entity's table (whose own write
    /// controls hide unless the caller may write it).
    pub async fn render_for(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        self.check_filters()?;
        let active = self.active(state)?;
        let panel = active.render_for(headers, state).await?;
        AdminTmpl {
            title: self.title.clone().unwrap_or_default(),
            nav: self.nav(&active.slug, state),
            panel,
        }
        .render()
        .map_err(render_err)
    }

    /// Apply a posted form to the entity it names (`_entity`, else the active one). An entity this
    /// panel doesn't list is refused before any gate is consulted: the panel's contents are part of
    /// what it permits, not merely of what it shows.
    pub async fn submit(
        &self,
        headers: &HeaderMap,
        client_ip: IpAddr,
        body: &[u8],
        state: &ViewState,
    ) -> Result<Outcome> {
        let posted = Posted::read(headers, body)?;
        let named = posted.one("_entity").map(str::to_string).or_else(|| state.entity.clone());
        let table = match named {
            Some(slug) => self.table(&slug).ok_or(Error::NotFound)?,
            None => self.active(state)?,
        };
        table.submit(headers, client_ip, body, state).await
    }

    /// The CSV export of the active table — see [`Table::csv`].
    #[cfg(feature = "csv")]
    pub async fn csv(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        self.active(state)?.csv(headers, state).await
    }

    /// The table `?entity=` names, else the first listed — with the shared filters attached.
    fn active(&self, state: &ViewState) -> Result<Table<'a>> {
        let chosen = match &state.entity {
            Some(slug) => self.table(slug).ok_or(Error::NotFound)?,
            None => self
                .items
                .iter()
                .find_map(|i| match i {
                    AdminItem::Entity(t) => Some(self.with_shared(t)),
                    _ => None,
                })
                .ok_or_else(|| {
                    Error::BadRequest("crud::ui(Admin): no entities listed".to_string())
                })?,
        };
        Ok(chosen)
    }

    fn table(&self, slug: &str) -> Option<Table<'a>> {
        self.items.iter().find_map(|i| match i {
            AdminItem::Entity(t) if t.slug == slug => Some(self.with_shared(t)),
            _ => None,
        })
    }

    /// Offer every shared filter to this table; `applicable_filters` drops the ones it has no column
    /// for (most of them, usually) without complaining.
    fn with_shared(&self, table: &Table<'a>) -> Table<'a> {
        let mut table = table.clone();
        for name in &self.filters {
            table.filters.push(FilterSpec {
                name: name.clone(),
                fixed: None,
                shared: true,
            });
        }
        table
    }

    fn nav(&self, active: &str, state: &ViewState) -> Vec<NavV> {
        self.items
            .iter()
            .map(|item| match item {
                AdminItem::Entity(t) => NavV::Entity {
                    label: t.title.clone().unwrap_or_else(|| t.slug.clone()),
                    // A nav link carries a filter only if this panel *shares* it and the entity it
                    // points at has a column for it. Everything else — a table's own filter, a
                    // shared one the target knows nothing about — stays behind: a link that
                    // silently narrows the page it lands on (or names a column that isn't there)
                    // is not navigation.
                    href: state.href_entity(self.base.as_deref(), &t.slug, |name| {
                        self.filters.iter().any(|shared| shared == name)
                            && self
                                .engine
                                .columns(&t.slug)
                                .is_ok_and(|cols| is_filterable(&cols, name))
                    }),
                    active: t.slug == active,
                },
                AdminItem::Group(name) => NavV::Group(name.clone()),
                AdminItem::Separator => NavV::Separator,
                AdminItem::Link { label, href } => {
                    NavV::Link { label: label.clone(), href: href.clone() }
                }
            })
            .collect()
    }

    /// A shared filter no listed entity has any column for is an error: every table would drop it, so
    /// the panel would render no control at all — which reads as a broken feature rather than a typo.
    fn check_filters(&self) -> Result<()> {
        for name in &self.filters {
            let known = self.items.iter().any(|i| match i {
                AdminItem::Entity(t) => {
                    self.engine.columns(&t.slug).is_ok_and(|cols| is_filterable(&cols, name))
                }
                _ => false,
            });
            if !known {
                return Err(Error::BadRequest(format!(
                    "crud::ui(Admin): cannot filter by '{name}': no listed entity has such a \
                     column or to-one relation"
                )));
            }
        }
        Ok(())
    }
}

