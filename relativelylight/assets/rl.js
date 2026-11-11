/* relativelylight — the relation picker's script, the one script the components ship (see
   crud::ui::JS). Without it a large relation still shows its selection and saves it unchanged; this
   adds the way to change it, and (with Crud::picker_create) the "+" that creates a missing row.

   A dialog holds an iframe of the Picker page, in one of two kinds:

   - **pick** (🔍, `.rl-pick`): the field (`.rl-picked`) holds the selection as badges plus one
     hidden input per id. The dialog edits a *copy* of it: OK writes the copy back, Cancel (or Esc)
     drops it, so the field is never touched until the operator says so. The Picker page is the
     same origin, so this script reads its radios and checkboxes directly on every load; the copy
     lives here, which is why it survives paging and searching inside the dialog. A to-one is the
     same code with the copy capped at one.
   - **new** ("+ New", `.rl-new` below a `<select>`, or the New button of a pick dialog whose field
     has `data-rl-new`): the iframe is the target's create form. When it saves, the page it lands
     on carries `.rl-created` with the new row's id and label; this script chooses that row — a
     selected option of the `<select>`, or a chip of the pick dialog's working selection, which OK
     then writes back as usual — and closes the dialog. The form underneath was never reloaded, so
     what was typed in it is still there.

   - **view** (a relation's label, `a.rl-view`, with Crud::picker_view): the iframe is the linked
     row, read-only, with Edit when the caller may update it. A saved edit's page carries
     `.rl-saved` with the row's key and new label; this script updates every link to that row,
     in the page and in the dialogs under it. Close returns to exactly where the operator was. A
     click with a modifier (a new tab) follows the link's own `href` instead.

   Dialogs stack: a create form's own relations have their 🔍 and "+", a viewed row's relations
   are links, and each opens a new dialog over the last. Only the top window runs this; it wires
   up each iframe's page when it loads (that page needs no script of its own). Create forms and
   viewed rows stop at MAX_DEPTH deep: the deepest one's "+" stays hidden and its links are text. (No closing script tag anywhere in this file, comments included: an app inlines
   it.) */
(() => {
  // A copy of this script inside one of our own iframes (an app whose bare shell includes it)
  // leaves the work to the window that opened the dialog.
  try {
    if (window.parent !== window && window.parent.__rlPicker) return;
  } catch (e) { /* a cross-origin parent: we are the top */ }
  window.__rlPicker = true;

  const MAX_DEPTH = 4;
  const stack = []; // the open dialogs, bottom first

  const el = (tag, cls, text, doc = document) => {
    const e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  };
  const button = (cls, text, onclick) => {
    const b = el('button', cls, text);
    b.type = 'button';
    b.onclick = onclick;
    return b;
  };

  // The current selection of a `.rl-picked` field, from its badges.
  function selection(field) {
    const chosen = new Map();
    for (const b of field.querySelectorAll('.rl-picked-list [data-id]')) {
      chosen.set(b.dataset.id, b.textContent);
    }
    return chosen;
  }

  // Write `chosen` into a `.rl-picked` field: its badges, and one hidden input per id.
  function commit(field, chosen) {
    const doc = field.ownerDocument;
    const list = field.querySelector('.rl-picked-list');
    list.replaceChildren();
    for (const old of field.querySelectorAll('input[type=hidden]')) old.remove();
    if (chosen.size === 0) list.append(el('span', 'text-muted', 'None', doc));
    for (const [id, label] of chosen) {
      const badge = el('span', 'badge text-bg-secondary', label, doc);
      badge.dataset.id = id;
      list.append(badge);
      const input = el('input', '', undefined, doc);
      input.type = 'hidden';
      input.name = field.dataset.rlName;
      input.value = id;
      field.append(input);
    }
  }

  // A row "New" created, chosen where it was asked for: the pick dialog's working selection, or
  // the `<select>` beside the button.
  function deliver(level, id, label) {
    const into = level.into;
    if (into.kind === 'pick') {
      if (!into.many) into.chosen.clear();
      into.chosen.set(id, label);
      showChips(into);
      tick(into);
      return;
    }
      let option = [...into.options].find((o) => o.value === id);
      if (!option) {
        option = el('option', '', label, into.ownerDocument);
        option.value = id;
        into.append(option);
      }
      if (!into.multiple) into.value = id;
      option.selected = true;
    into.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // How many create forms and viewed rows are open (a pick dialog opens no further levels).
  function depth() {
    return stack.filter((l) => l.kind !== 'pick').length;
  }

  // Each page of a dialog's iframe, and the top page once: let its buttons and links open dialogs,
  // and show the buttons — all but "+" when the dialogs are already MAX_DEPTH deep, where a
  // relation link is text too (following it would load the app's page inside the dialog).
  function wire(doc) {
    doc.addEventListener('click', (e) => {
      const b = e.target.closest && e.target.closest('.rl-pick, .rl-new, a.rl-view');
      if (!b) return;
      if (b.matches('a.rl-view')) {
        if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
        e.preventDefault();
        if (!b.hasAttribute('href')) return;
      }
      open(b);
    });
    const deep = depth() >= MAX_DEPTH;
    for (const b of doc.querySelectorAll('.rl-pick')) b.hidden = false;
    for (const b of doc.querySelectorAll('.rl-new')) b.hidden = deep;
    if (deep && doc !== document) {
      for (const a of doc.querySelectorAll('a.rl-view')) a.removeAttribute('href');
    }
  }

  // Every document a link to a row may be in: the page, and each open dialog's page.
  function documents() {
    const docs = [document];
    for (const l of stack) if (l.frame.contentDocument) docs.push(l.frame.contentDocument);
    return docs;
  }

  // A 🔍, a "+ New" or a relation link was clicked, in the page or in a dialog's page.
  function open(trigger) {
    if (trigger.classList.contains('rl-view')) {
      push({ kind: 'view', title: trigger.textContent.trim(), src: trigger.dataset.rlView });
      return;
    }
    if (trigger.classList.contains('rl-new')) {
      push({
        kind: 'new',
        into: trigger.parentElement.querySelector('select'),
        title: trigger.dataset.rlTitle,
        src: trigger.dataset.rlSrc,
      });
      return;
    }
    const field = trigger.closest('.rl-picked');
    push({
      kind: 'pick',
      field,
      many: field.dataset.rlMany === 'true',
      chosen: selection(field),
      title: field.dataset.rlTitle,
      src: field.dataset.rlSrc,
      create: field.dataset.rlNew || '',
    });
  }

  function push(level) {
    const kind = level.kind;
    if (kind !== 'pick' && depth() >= MAX_DEPTH) return;
    build(level);
    stack.push(level);
    level.dialog.style.setProperty('--rl-depth', stack.length - 1);
    level.heading.textContent = stack.map((l) => l.title).join(' › ');
    if (kind === 'pick') showChips(level);
    level.frame.src = level.src;
    level.dialog.showModal();
  }

  function build(level) {
    const dialog = el('dialog', 'rl-picker');
    const card = el('div', 'card h-100');
    const head = el('div', 'card-header');
    const top = el('div', 'd-flex justify-content-between align-items-center mb-1');
    level.heading = el('h5', 'mb-0');
    const close = button('btn-close', undefined, () => dialog.close());
    close.setAttribute('aria-label', 'Cancel');
    top.append(level.heading, close);
    head.append(top);
    if (level.kind === 'pick') {
      level.chips = el('div', 'rl-picker-chips d-flex flex-wrap gap-1');
      head.append(level.chips);
    }
    const frame = el('iframe', 'rl-picker-frame');
    frame.title = level.kind === 'pick' ? 'Choose' : level.title;
    frame.addEventListener('load', () => loaded(level));
    const foot = el('div', 'card-footer d-flex align-items-center gap-2');
    // A pick dialog over a field with "+": create a row and add it to this selection. Not past
    // MAX_DEPTH, as for the "+ New" buttons inside the dialogs.
    if (level.kind === 'pick' && level.create && depth() < MAX_DEPTH) {
      const add = button('btn btn-primary btn-sm', '+ New', () => push({
        kind: 'new',
        into: level,
        title: 'New ' + level.title,
        src: level.create,
      }));
      foot.append(add);
    }
    // The buttons on the right: Cancel and OK for a pick; for a form or a row, the page's own
    // buttons and this dialog's Cancel / Close, rebuilt on each page load (`actions`).
    level.right = el('div', 'ms-auto d-flex gap-2');
    level.dismiss = button('btn btn-secondary', level.kind === 'view' ? 'Close' : 'Cancel', () => dialog.close());
    level.right.append(level.dismiss);
    if (level.kind === 'pick') {
      level.right.append(button('btn btn-primary', 'OK', () => {
        commit(level.field, level.chosen);
        dialog.close();
      }));
    }
    foot.append(level.right);
    card.append(head, frame, foot);
    dialog.append(card);
    // Esc, ✕, Cancel, OK and a delivered row all end here: the dialog is the top one, so it leaves
    // the stack and the page.
    dialog.addEventListener('close', () => {
      const i = stack.indexOf(level);
      if (i >= 0) stack.splice(i, 1);
      dialog.remove();
    });
    level.dialog = dialog;
    level.frame = frame;
    document.body.append(dialog);
  }

  function loaded(level) {
    const doc = level.frame.contentDocument;
    if (!doc) return;
    if (level.kind === 'new') {
      const made = doc.querySelector('.rl-created');
      if (made) {
        deliver(level, made.dataset.id, made.dataset.label);
        level.dialog.close();
        return;
      }
    }
    if (level.kind !== 'pick') actions(level, doc);
    if (level.kind === 'view') {
      const saved = doc.querySelector('.rl-saved');
      if (saved) {
        relabel(saved.dataset.rlKey, saved.dataset.label);
        level.title = saved.dataset.label;
        level.heading.textContent = stack.slice(0, stack.indexOf(level) + 1).map((l) => l.title).join(' › ');
      }
    }
    if (level.kind === 'pick') sync(level, doc);
    wire(doc);
  }

  // A form's or a row's page puts its buttons in `.rl-foot` (Edit; Cancel and Save). They belong in
  // this dialog's footer, as in the table's own dialogs: hide them there and put a button here
  // that clicks each one. The page's own Cancel replaces this dialog's (it goes back to the row,
  // not out); otherwise Close follows a row's buttons, as in the table's View, and Cancel comes
  // before a form's Create, as in its New.
  function actions(level, doc) {
    const foot = doc.querySelector('.rl-foot');
    const mirrored = [];
    let ownCancel = false;
    if (foot) {
      for (const b of foot.querySelectorAll('a.btn, button.btn')) {
        if (b.classList.contains('btn-secondary')) ownCancel = true;
        mirrored.push(button(b.className, b.textContent.trim(), () => b.click()));
      }
      foot.hidden = true;
    }
    level.right.replaceChildren();
    if (ownCancel) level.right.append(...mirrored);
    else if (level.kind === 'view') level.right.append(...mirrored, level.dismiss);
    else level.right.append(level.dismiss, ...mirrored);
  }

  // An edit in a view dialog renamed a row: every link to it says so now, without a reload (which
  // would lose a form being filled in underneath).
  function relabel(key, label) {
    for (const doc of documents()) {
      for (const a of doc.querySelectorAll('a.rl-view')) {
        if (a.dataset.rlKey === key) a.textContent = label;
      }
    }
  }

  // The working selection, as removable chips: how a row is dropped without finding it again in
  // the table, and how a to-one is cleared.
  function showChips(level) {
    const chips = level.chips;
    chips.replaceChildren();
    if (level.chosen.size === 0) chips.append(el('span', 'text-muted small', 'Nothing chosen'));
    for (const [id, label] of level.chosen) {
      const chip = el('span', 'badge text-bg-secondary d-inline-flex align-items-center gap-1', label);
      const x = button('btn-close btn-close-white rl-chip-x', undefined, () => {
        level.chosen.delete(id);
        showChips(level);
        tick(level);
      });
      x.setAttribute('aria-label', 'Remove ' + label);
      chip.append(x);
      chips.append(chip);
    }
  }

  function rows(level) {
    const doc = level.frame.contentDocument;
    return doc ? doc.querySelectorAll('input.rl-pick-row') : [];
  }

  function tick(level) {
    for (const input of rows(level)) input.checked = level.chosen.has(input.value);
  }

  // Each page a pick dialog loads: show what is chosen, and follow the operator's clicks.
  function sync(level) {
    tick(level);
    for (const input of rows(level)) {
      input.addEventListener('change', () => {
        if (!level.many) level.chosen.clear();
        if (input.checked) level.chosen.set(input.value, input.dataset.label);
        else level.chosen.delete(input.value);
        showChips(level);
      });
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => wire(document));
  else wire(document);
})();
