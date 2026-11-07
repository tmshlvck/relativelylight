# Upgrading from 0.4 to 0.5

**0.5 is not released yet**; this file collects the steps as they land on `main`.
[CHANGELOG.md](../CHANGELOG.md) has the full list.

## 1. `Auth`'s page callbacks get the request

`Auth::login_shell`, `Auth::profile_shell`, `Auth::csrf_rejection` and `Csrf::on_reject` are now
handed the request's `http::request::Parts`, and `Csrf::reject` takes it. Each is a compile error
until you add the argument:

| 0.4 | 0.5 |
|---|---|
| `.login_shell(\|form\| …)` | `.login_shell(\|form, req\| …)` |
| `.profile_shell(\|frag, who\| …)` | `.profile_shell(\|frag, who, req\| …)` |
| `.csrf_rejection(\|\| …)` / `.on_reject(\|\| …)` | `.csrf_rejection(\|req\| …)` / `.on_reject(\|req\| …)` |
| `csrf.reject()` | `csrf.reject(&parts)`: extract `parts: http::request::Parts` in the handler in place of `HeaderMap`, and read `parts.headers` |

A function passed by name (`.login_shell(login_shell)`) gains a `req: &Parts` parameter. Ignore it
(`_req`) to keep 0.4's pages, or use it to render the chrome the rest of your app renders, such as
the timezone picker ([TIME.md §3](TIME.md#3-the-picker-and-its-handler)). A shell that rendered a
reduced navbar because it had no request can now render the full one.
