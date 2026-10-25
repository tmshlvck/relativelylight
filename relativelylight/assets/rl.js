/* relativelylight — the relation picker's script, the one script the components ship (see
   crud::ui::JS). Without it a large relation still shows its selection and saves it unchanged; this
   adds the way to change it.

   A field (`.rl-picked`) holds the selection as badges plus one hidden input per id. Its button
   opens a single shared modal dialog over an iframe of the Picker page. The dialog edits a *copy*
   of the selection: OK writes the copy back into the field's badges and hidden inputs, Cancel (or
   Esc) drops it, so the field is never touched until the operator says so. The Picker page is the
   same origin, so this script reads its radios and checkboxes directly on every load; the copy
   lives here, which is why it survives paging and searching inside the dialog. A to-one is the
   same code with the copy capped at one. (No closing script tag anywhere in this file, comments
   included: an app inlines it.) */
(() => {
  let dialog, frame, chips, heading, field, many, chosen;

  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  };

  function build() {
    dialog = el('dialog', 'rl-picker');
    const card = el('div', 'card h-100');
    const head = el('div', 'card-header');
    const top = el('div', 'd-flex justify-content-between align-items-center mb-1');
    heading = el('h5', 'mb-0');
    const close = el('button', 'btn-close');
    close.type = 'button';
    close.setAttribute('aria-label', 'Cancel');
    close.onclick = () => dialog.close();
    top.append(heading, close);
    chips = el('div', 'rl-picker-chips d-flex flex-wrap gap-1');
    head.append(top, chips);
    frame = el('iframe', 'rl-picker-frame');
    frame.title = 'Choose';
    frame.addEventListener('load', sync);
    const foot = el('div', 'card-footer text-end');
    const cancel = el('button', 'btn btn-secondary', 'Cancel');
    cancel.type = 'button';
    cancel.onclick = () => dialog.close();
    const ok = el('button', 'btn btn-primary ms-2', 'OK');
    ok.type = 'button';
    ok.onclick = () => { commit(); dialog.close(); };
    foot.append(cancel, ok);
    card.append(head, frame, foot);
    dialog.append(card);
    document.body.append(dialog);
  }

  function open(button) {
    if (!dialog) build();
    field = button.closest('.rl-picked');
    many = field.dataset.rlMany === 'true';
    chosen = new Map();
    for (const b of field.querySelectorAll('.rl-picked-list [data-id]')) {
      chosen.set(b.dataset.id, b.textContent);
    }
    heading.textContent = field.dataset.rlTitle;
    showChips();
    frame.src = field.dataset.rlSrc;
    dialog.showModal();
  }

  // The working selection, as removable chips: how a row is dropped without finding it again in
  // the table, and how a to-one is cleared.
  function showChips() {
    chips.replaceChildren();
    if (chosen.size === 0) chips.append(el('span', 'text-muted small', 'Nothing chosen'));
    for (const [id, label] of chosen) {
      const chip = el('span', 'badge text-bg-secondary d-inline-flex align-items-center gap-1', label);
      const x = el('button', 'btn-close btn-close-white rl-chip-x');
      x.type = 'button';
      x.setAttribute('aria-label', 'Remove ' + label);
      x.onclick = () => { chosen.delete(id); showChips(); tick(); };
      chip.append(x);
      chips.append(chip);
    }
  }

  function rows() {
    const doc = frame.contentDocument;
    return doc ? doc.querySelectorAll('input.rl-pick-row') : [];
  }

  function tick() {
    for (const input of rows()) input.checked = chosen.has(input.value);
  }

  // Each page the iframe loads: show what is chosen, and follow the operator's clicks.
  function sync() {
    tick();
    for (const input of rows()) {
      input.addEventListener('change', () => {
        if (!many) chosen.clear();
        if (input.checked) chosen.set(input.value, input.dataset.label);
        else chosen.delete(input.value);
        showChips();
      });
    }
  }

  function commit() {
    const list = field.querySelector('.rl-picked-list');
    list.replaceChildren();
    for (const old of field.querySelectorAll('input[type=hidden]')) old.remove();
    if (chosen.size === 0) list.append(el('span', 'text-muted', 'None'));
    for (const [id, label] of chosen) {
      const badge = el('span', 'badge text-bg-secondary', label);
      badge.dataset.id = id;
      list.append(badge);
      const input = el('input');
      input.type = 'hidden';
      input.name = field.dataset.rlName;
      input.value = id;
      field.append(input);
    }
  }

  document.addEventListener('click', (e) => {
    const button = e.target.closest && e.target.closest('.rl-pick');
    if (button) open(button);
  });
  const reveal = () => { for (const b of document.querySelectorAll('.rl-pick')) b.hidden = false; };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', reveal);
  else reveal();
})();
