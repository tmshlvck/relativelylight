/* relativelylight — the timezone picker, and the first visit's default (docs/TIME.md). Inline once
   per page, in a script element at the end of the body: relativelylight::time::JS.
   (No closing script tag anywhere in this file, including in a comment: it would end the element.)

   The zone rides in the rl_tz cookie, which the server reads to render every time (relativelylight::
   time::Tz). Without the cookie, or with a name it doesn't know, the server renders UTC. */
(function () {
  'use strict';
  var COOKIE = 'rl_tz';

  function browserZone() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch (e) { return 'UTC'; }
  }
  function hasCookie() {
    return document.cookie.split('; ').some(function (c) { return c.indexOf(COOKIE + '=') === 0; });
  }
  // Set the zone and render again. Only reload once the cookie took, so a browser refusing cookies
  // doesn't reload forever.
  function choose(zone) {
    document.cookie = COOKIE + '=' + encodeURIComponent(zone) + '; Path=/; Max-Age=31536000; SameSite=Lax';
    if (hasCookie()) location.reload();
  }

  // A first visit: the browser's own zone, once. A zone chosen later is never overwritten.
  if (!hasCookie()) { choose(browserZone()); return; }

  document.querySelectorAll('[data-rl-tz] input[list]').forEach(function (input) {
    var browser = input.closest('[data-rl-tz]').getAttribute('data-rl-tz-browser');
    var known = {};
    Array.prototype.forEach.call(input.list.options, function (o) { known[o.value] = true; });
    var shown = input.value;
    // Empty while focused, so the whole list is offered rather than the matches for the current zone.
    input.addEventListener('focus', function () { input.placeholder = shown; input.value = ''; });
    input.addEventListener('blur', function () { if (input.value === '') input.value = shown; });
    input.addEventListener('change', function () {
      var v = input.value.trim();
      if (v === '') return;
      choose(v === browser ? browserZone() : known[v] ? v : 'UTC');
    });
  });
})();
