// relativelylight — the passkey script (docs/AUTH.md §5l). Served at /auth/passkey.js.
//
// A button `data-rl-passkey="get"` or `"create"` sits in a form with the ceremony's options in a
// `<script type="application/json" data-rl-passkey-options>`, and an empty
// `<input name="passkey_response">`. On click: run the browser's ceremony, put the answer (JSON) in the
// field, submit the form. The server verifies; this script decides nothing.
//
// Loaded once per page however many forms include it; one listener on the document serves them all.
(function () {
  "use strict";
  if (window.__rlPasskey) return;
  window.__rlPasskey = true;

  // base64url (no padding) <-> ArrayBuffer — the encoding the server uses for every binary field.
  function toBuf(s) {
    var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var bin = atob(b64), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function toB64(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function ids(list) {
    return (list || []).map(function (c) {
      var o = { type: c.type, id: toBuf(c.id) };
      if (c.transports) o.transports = c.transports;
      return o;
    });
  }

  function creationOptions(o) {
    var pk = Object.assign({}, o.publicKey);
    pk.challenge = toBuf(pk.challenge);
    pk.user = Object.assign({}, pk.user, { id: toBuf(pk.user.id) });
    pk.excludeCredentials = ids(pk.excludeCredentials);
    return { publicKey: pk };
  }
  function requestOptions(o) {
    var pk = Object.assign({}, o.publicKey);
    pk.challenge = toBuf(pk.challenge);
    pk.allowCredentials = ids(pk.allowCredentials);
    return { publicKey: pk };
  }

  function registration(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: toB64(cred.rawId),
      type: cred.type,
      extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        attestationObject: toB64(r.attestationObject),
        clientDataJSON: toB64(r.clientDataJSON),
        transports: r.getTransports ? r.getTransports() : undefined,
      },
    };
  }
  function assertion(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: toB64(cred.rawId),
      type: cred.type,
      extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        authenticatorData: toB64(r.authenticatorData),
        clientDataJSON: toB64(r.clientDataJSON),
        signature: toB64(r.signature),
        userHandle: r.userHandle ? toB64(r.userHandle) : null,
      },
    };
  }

  // A message next to the button, for the cases the server never sees (cancelled, unsupported).
  function say(button, text) {
    var note = button.parentNode.querySelector("[data-rl-passkey-note]");
    if (!note) {
      note = document.createElement("p");
      note.className = "small text-danger mt-2";
      note.setAttribute("data-rl-passkey-note", "");
      button.insertAdjacentElement("afterend", note);
    }
    note.textContent = text;
  }

  // "Sign in with a passkey" on the login page: one click opens the browser's prompt. The form posts to
  // the same route a browser without this script uses, asking for JSON (the challenge and where to
  // send the answer), then posts the answer as a form. If anything gets in the way — no JSON (a
  // lockout page), or a browser that won't open the prompt after a fetch — the form falls back to
  // its plain submit, the page with its own button.
  function hidden(form, name, value) {
    var input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    form.appendChild(input);
  }
  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    if (!form.matches || !form.matches("form[data-rl-passkey-login]")) return;
    if (form.hasAttribute("data-rl-fallback") || !window.PublicKeyCredential || !window.fetch) return;
    ev.preventDefault();
    var button = form.querySelector("button");
    var fallback = function () {
      form.setAttribute("data-rl-fallback", "");
      form.submit();
    };
    if (button) button.disabled = true;
    fetch(form.action, {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(new FormData(form)).toString(),
    })
      .then(function (r) {
        var json = (r.headers.get("content-type") || "").indexOf("application/json") >= 0;
        if (!r.ok || !json) throw new Error("no challenge");
        return r.json();
      })
      .then(function (ask) {
        return navigator.credentials.get(requestOptions(ask.options)).then(assertion).then(
          function (answer) {
            var post = document.createElement("form");
            post.method = "post";
            post.action = ask.action;
            post.hidden = true;
            hidden(post, "_csrf", form.querySelector("input[name=_csrf]").value);
            hidden(post, "passkey_challenge", ask.challenge);
            hidden(post, "passkey_response", JSON.stringify(answer));
            document.body.appendChild(post);
            post.submit();
          },
          function (err) {
            // Closed, timed out, or refused for lack of a direct click: the next click goes to the
            // page that has its own button.
            if (button) button.disabled = false;
            form.setAttribute("data-rl-fallback", "");
            say(button, err && err.name === "NotAllowedError"
              ? "The passkey prompt was closed. Click again to continue."
              : "The passkey didn't work here. Click again to continue.");
          }
        );
      }, fallback);
  });

  document.addEventListener("click", function (ev) {
    var button = ev.target.closest && ev.target.closest("[data-rl-passkey]");
    if (!button) return;
    ev.preventDefault();
    var form = button.form || button.closest("form");
    var holder = form && form.querySelector("[data-rl-passkey-options]");
    var field = form && form.querySelector("input[name=passkey_response]");
    if (!holder || !field) return;
    if (!window.PublicKeyCredential || !navigator.credentials) {
      say(button, "This browser doesn't support passkeys.");
      return;
    }
    var options = JSON.parse(holder.textContent);
    var create = button.getAttribute("data-rl-passkey") === "create";
    button.disabled = true;
    var ceremony = create
      ? navigator.credentials.create(creationOptions(options)).then(registration)
      : navigator.credentials.get(requestOptions(options)).then(assertion);
    ceremony.then(
      function (answer) {
        field.value = JSON.stringify(answer);
        // The confirm-it's-you block may sit in a form whose other inputs the user left empty on
        // purpose: submit as is, the server reads the passkey first.
        if (form.requestSubmit) form.requestSubmit(); else form.submit();
      },
      function (err) {
        button.disabled = false;
        say(button, err && err.name === "NotAllowedError"
          ? "The passkey prompt was closed or timed out. Try again."
          : "The passkey didn't work here: " + (err && err.message ? err.message : err));
      }
    );
  });
})();
