//! [`Form`] — the same create/edit form [`Table`](super::Table) shows in its dialog, standalone,
//! for an app's own pages.

use super::state::ViewState;
use super::widgets::{self, FieldV, Widget};
use super::{
    apply, banner, check_fields, check_widgets, csrf_token, render_err, renders, Outcome, Surface,
};
use crate::authz::{Decision, Operation};
use crate::crud::engine::{Engine, Error, ListQuery, Result};
use crate::time::Tz;
use askama::Template;
use http::HeaderMap;
use std::net::IpAddr;

#[derive(Template)]
#[template(path = "form.html")]
struct FormTmpl {
    dom_id: String,
    has_header: bool,
    title: String,
    description: String,
    op: &'static str,
    id: String,
    csrf: String,
    saved: String,
    errors: Vec<String>,
    fields: Vec<FieldV>,
    cancel_href: String,
    submit_label: String,
}

/// A standalone create/edit form for one registered entity — the same form [`Table`] shows in its
/// dialog, without the table.
///
/// This is the building block for an app's **own** pages, where [`Admin`] is the wrong shape: a signup
/// form, a "new ticket" page, a settings screen. It reads the entity's columns, so the widgets, the
/// required markers, the enum dropdowns, the relation pickers, the datetime handling and the
/// validation messages all come for free and stay in step with the model.
///
/// ```ignore
/// // GET /ticket/new
/// let html = Form::new(&engine, "ticket")
///     .title("New ticket")
///     .fields(["subject", "body", "priority"])
///     .redirect("/tickets/{id}")
///     .render_for(&headers, &state).await?;   // 401/403 rather than a form that can't submit
/// ```
pub struct Form<'a> {
    engine: &'a Engine,
    slug: String,
    dom_id: Option<String>,
    title: Option<String>,
    description: Option<String>,
    heading: Option<bool>,
    edit_id: Option<String>,
    fields: Vec<String>,
    omit: Vec<String>,
    submit_label: Option<String>,
    saved_message: Option<String>,
    cancel_href: Option<String>,
    redirect: Option<String>,
    picker_threshold: u64,
}

impl<'a> Form<'a> {
    /// A form that **creates** a row of `slug`. Add [`edit`](Form::edit) to update one.
    pub fn new(engine: &'a Engine, slug: impl Into<String>) -> Self {
        Self {
            engine,
            slug: slug.into(),
            dom_id: None,
            title: None,
            description: None,
            heading: None,
            edit_id: None,
            fields: Vec::new(),
            omit: Vec::new(),
            submit_label: None,
            saved_message: None,
            cancel_href: None,
            redirect: None,
            picker_threshold: 20,
        }
    }

    /// Edit this existing row: the form renders its current values and saves over them.
    pub fn edit(mut self, id: impl Into<String>) -> Self {
        self.edit_id = Some(id.into());
        self
    }
    /// Heading in the card header. Setting a title (or a description) shows the header; without
    /// either there is none, since an app page usually has its own heading already.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
    /// A muted line under the title — what this form is for.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
    /// Force the card header on or off, overriding the "on if titled" default.
    pub fn heading(mut self, on: bool) -> Self {
        self.heading = Some(on);
        self
    }
    /// Render **only** these columns, in this order. Without it the form shows every writable
    /// column, which is the admin's default and rarely what a user-facing form wants.
    pub fn fields<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.fields = names.into_iter().map(Into::into).collect();
        self
    }
    /// Drop these columns, keeping the rest (the complement of [`fields`](Form::fields)).
    pub fn omit<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.omit = names.into_iter().map(Into::into).collect();
        self
    }
    /// Text on the submit button. Default: `Save`.
    pub fn submit_label(mut self, label: impl Into<String>) -> Self {
        self.submit_label = Some(label.into());
        self
    }
    /// The confirmation shown after a save when there is no [`redirect`](Form::redirect).
    /// Default: `Saved.`
    pub fn saved_message(mut self, msg: impl Into<String>) -> Self {
        self.saved_message = Some(msg.into());
        self
    }
    /// Show a Cancel link to this URL. Without it there is no Cancel button.
    pub fn cancel(mut self, href: impl Into<String>) -> Self {
        self.cancel_href = Some(href.into());
        self
    }
    /// Where [`submit`](Form::submit) points after a successful save. `{id}` is replaced with the
    /// saved row's id, so `"/tickets/{id}"` lands on the new row. Without it the form redirects to
    /// itself and shows [`saved_message`](Form::saved_message).
    pub fn redirect(mut self, url: impl Into<String>) -> Self {
        self.redirect = Some(url.into());
        self
    }
    /// See [`Table::picker_threshold`].
    pub fn picker_threshold(mut self, n: u64) -> Self {
        self.picker_threshold = n;
        self
    }
    /// Namespaces the fragment's DOM id, so two forms for the same entity can share a page.
    pub fn dom_id(mut self, id: impl Into<String>) -> Self {
        self.dom_id = Some(id.into());
        self
    }

    /// Render the form, refusing rather than rendering one the caller could never submit:
    /// `Err(Error::Unauthorized)` (→ `401`) when the gate wants a login, `Err(Error::Forbidden)`
    /// (→ `403`) when it simply isn't permitted. A page handler turns the first into a redirect to
    /// the login page.
    ///
    /// `state` carries a rejected write's messages; [`ViewState::default`] is a fresh form. A
    /// `?saved=1` in your redirect target shows the saved message.
    pub async fn render_for(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        let op = if self.edit_id.is_some() { Operation::Update } else { Operation::Create };
        match self.engine.decide(&self.slug, op, headers).await {
            Decision::Allow => {}
            Decision::NeedsLogin => return Err(Error::Unauthorized),
            Decision::Denied => return Err(Error::Forbidden),
        }
        let cols = self.engine.columns(&self.slug)?;
        check_widgets(&self.slug, &cols)?;
        check_fields(&self.slug, &cols, &self.fields, &self.omit, self.edit_id.is_none())?;
        let tz = Tz::from_headers(headers);
        let row = match &self.edit_id {
            Some(id) => Some(self.engine.get(&self.slug, id).await?),
            None => None,
        };
        let fields = widgets::fields(
            self.engine,
            &cols,
            &|name| renders(&self.fields, &self.omit, name),
            row.as_ref(),
            state,
            &tz,
            self.picker_threshold,
        )
        .await?;
        FormTmpl {
            dom_id: self.dom_id.clone().unwrap_or_default(),
            has_header: self
                .heading
                .unwrap_or(self.title.is_some() || self.description.is_some()),
            title: self.title.clone().unwrap_or_else(|| self.slug.clone()),
            description: self.description.clone().unwrap_or_default(),
            op: if self.edit_id.is_some() { "update" } else { "create" },
            id: self.edit_id.clone().unwrap_or_default(),
            csrf: csrf_token(self.engine, headers),
            saved: match state.saved {
                true => self.saved_message.clone().unwrap_or_else(|| "Saved.".into()),
                false => String::new(),
            },
            errors: banner(state, &fields),
            fields,
            cancel_href: self.cancel_href.clone().unwrap_or_default(),
            submit_label: self.submit_label.clone().unwrap_or_else(|| "Save".into()),
        }
        .render()
        .map_err(render_err)
    }

    /// Apply this form's posted body. On success the target is [`redirect`](Form::redirect) with
    /// `{id}` filled in, else `?saved=1` on the current URL.
    pub async fn submit(
        &self,
        headers: &HeaderMap,
        client_ip: IpAddr,
        body: &[u8],
        state: &ViewState,
    ) -> Result<Outcome> {
        let cols = self.engine.columns(&self.slug)?;
        let shown = |name: &str| renders(&self.fields, &self.omit, name);
        let surface = Surface {
            engine: self.engine,
            slug: &self.slug,
            renders: &shown,
            query: ListQuery::default(),
        };
        match apply(&surface, &cols, headers, client_ip, body, state).await? {
            Outcome::Done(to) => Ok(Outcome::Done(match &self.redirect {
                // `to` is `?…#row-{id}` — the id is what a redirect template wants.
                Some(url) => url.replace("{id}", to.rsplit("#row-").next().unwrap_or_default()),
                None => "?saved=1".to_string(),
            })),
            invalid => Ok(invalid),
        }
    }
}

