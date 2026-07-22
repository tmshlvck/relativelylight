/*!
 * rl-time.js — timezone-aware datetime helpers for relativelylight-based apps.
 *
 * Contract: the DB and every API speak **integer Unix seconds, UTC**. This file does all
 * humanization on the client. Include it once in your page shell, after Alpine.js. It defines:
 *
 *   window.RLTime          pure formatting/conversion functions (usable on any page)
 *   $store.tz              the current timezone selection (Alpine store, reactive)
 *   window.rlTzPicker()    Alpine component backing the dropdown in TZ_PICKER_HTML
 *
 * The app chooses the timezone policy (see docs/TIME.md) via an optional global `window.RL_TZ`
 * set BEFORE Alpine initializes:
 *
 *   window.RL_TZ = {
 *     mode: 'utc' | 'browser' | 'zone',   // initial selection (default 'utc')
 *     zone: 'Europe/Prague',              // IANA id, used when mode === 'zone'
 *     persist: 'session' | 'local' | null,// remember the picker choice (default: none)
 *     withUtc: false,                     // table cells show "local (UTC)" when true
 *     onChange: function (sel) { ... },   // called after every change (e.g. PUT to a profile API)
 *   };
 *
 * Without this file, datetime columns fall back to UTC (see table.html).
 */
;(function (global) {
  'use strict';

  // Curated IANA zones, one representative per UTC offset (−12 … +14). DST is handled by Intl at
  // format time, so these stay correct year-round. Extend/replace via window.RL_TZ.zones if needed.
  var ZONES = [
    { id: 'Etc/GMT+12',         label: '(UTC−12:00) Baker Island' },
    { id: 'Pacific/Pago_Pago',  label: '(UTC−11:00) Samoa' },
    { id: 'Pacific/Honolulu',   label: '(UTC−10:00) Hawaii' },
    { id: 'America/Anchorage',  label: '(UTC−09:00) Alaska' },
    { id: 'America/Los_Angeles',label: '(UTC−08:00) Pacific (US & Canada)' },
    { id: 'America/Denver',     label: '(UTC−07:00) Mountain (US & Canada)' },
    { id: 'America/Chicago',    label: '(UTC−06:00) Central (US & Canada)' },
    { id: 'America/New_York',   label: '(UTC−05:00) Eastern (US & Canada)' },
    { id: 'America/Halifax',    label: '(UTC−04:00) Atlantic' },
    { id: 'America/Sao_Paulo',  label: '(UTC−03:00) São Paulo' },
    { id: 'Atlantic/South_Georgia', label: '(UTC−02:00) South Georgia' },
    { id: 'Atlantic/Azores',    label: '(UTC−01:00) Azores' },
    { id: 'Europe/London',      label: '(UTC±00:00) London / Dublin' },
    { id: 'Europe/Prague',      label: '(UTC+01:00) Central Europe (Prague)' },
    { id: 'Europe/Athens',      label: '(UTC+02:00) Eastern Europe (Athens)' },
    { id: 'Europe/Moscow',      label: '(UTC+03:00) Moscow / Istanbul' },
    { id: 'Asia/Dubai',         label: '(UTC+04:00) Dubai' },
    { id: 'Asia/Karachi',       label: '(UTC+05:00) Karachi' },
    { id: 'Asia/Kolkata',       label: '(UTC+05:30) India' },
    { id: 'Asia/Dhaka',         label: '(UTC+06:00) Dhaka' },
    { id: 'Asia/Bangkok',       label: '(UTC+07:00) Bangkok / Jakarta' },
    { id: 'Asia/Shanghai',      label: '(UTC+08:00) China / Singapore' },
    { id: 'Asia/Tokyo',         label: '(UTC+09:00) Japan / Korea' },
    { id: 'Australia/Sydney',   label: '(UTC+10:00) Sydney' },
    { id: 'Pacific/Noumea',     label: '(UTC+11:00) New Caledonia' },
    { id: 'Pacific/Auckland',   label: '(UTC+12:00) Auckland' },
    { id: 'Pacific/Kiritimati', label: '(UTC+14:00) Kiritimati' },
  ];

  // Resolve a {mode, zone} selection to a concrete IANA zone id (or 'UTC').
  function resolveZone(sel) {
    sel = sel || {};
    if (sel.mode === 'browser') {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    }
    if (sel.mode === 'zone' && sel.zone) return sel.zone;
    return 'UTC';
  }

  function isSet(sec) {
    return !(sec === null || sec === undefined || sec === '' || Number(sec) === 0 || isNaN(Number(sec)));
  }

  // Wall-clock parts of an instant (Unix seconds) in `zone`, plus the zone's short name.
  function partsIn(sec, zone) {
    var d = new Date(Number(sec) * 1000);
    var dtf = new Intl.DateTimeFormat('en-US', {
      timeZone: zone, hourCycle: 'h23',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      timeZoneName: 'short',
    });
    var o = {};
    dtf.formatToParts(d).forEach(function (p) { if (p.type !== 'literal') o[p.type] = p.value; });
    return o; // { year, month, day, hour, minute, second, timeZoneName }
  }

  // UTC offset (minutes) of `zone` at instant `sec`. Used to convert form input back to UTC.
  function offsetMinutes(zone, sec) {
    var p = partsIn(sec, zone);
    var asUTC = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second);
    return Math.round((asUTC - Number(sec) * 1000) / 60000);
  }

  // "YYYY-MM-DD HH:MM:SS <TZ>" in the selected zone (blank when unset/0).
  function fmt(sec, sel) {
    if (!isSet(sec)) return '';
    var p = partsIn(sec, resolveZone(sel));
    return p.year + '-' + p.month + '-' + p.day + ' ' + p.hour + ':' + p.minute + ':' + p.second + ' ' + p.timeZoneName;
  }

  // Explicit UTC, regardless of the current selection — for the "always show UTC" case.
  function fmtUtc(sec) {
    if (!isSet(sec)) return '';
    var p = partsIn(sec, 'UTC');
    return p.year + '-' + p.month + '-' + p.day + ' ' + p.hour + ':' + p.minute + ':' + p.second + ' UTC';
  }

  // Selected-zone time with the UTC instant in parentheses:
  //   "2026-07-21 23:00:00 GMT+2 (2026-07-21 21:00:00 UTC)".
  // When the selection already resolves to UTC the parenthetical is dropped (it would be identical).
  function fmtWithUtc(sec, sel) {
    if (!isSet(sec)) return '';
    var main = fmt(sec, sel);
    return resolveZone(sel) === 'UTC' ? main : main + ' (' + fmtUtc(sec) + ')';
  }

  // Instant (Unix seconds) → naive "YYYY-MM-DDTHH:MM:SS" wall-clock in the selected zone, for
  // feeding an <input type="datetime-local"> (which has no timezone of its own).
  function toInput(sec, sel) {
    if (!isSet(sec)) return '';
    var p = partsIn(sec, resolveZone(sel));
    return p.year + '-' + p.month + '-' + p.day + 'T' + p.hour + ':' + p.minute + ':' + p.second;
  }

  // Naive datetime-local string (a wall-clock in the selected zone) → Unix seconds (UTC).
  // Two-pass offset resolution makes this correct across DST transitions.
  function fromInput(str, sel) {
    if (!str) return null;
    var m = str.split('T');
    if (m.length < 2) return null;
    var dp = m[0].split('-').map(Number), tp = m[1].split(':').map(Number);
    var asUTC = Date.UTC(dp[0], (dp[1] || 1) - 1, dp[2] || 1, tp[0] || 0, tp[1] || 0, tp[2] || 0);
    var zone = resolveZone(sel);
    if (zone === 'UTC') return Math.floor(asUTC / 1000);
    var off1 = offsetMinutes(zone, asUTC / 1000);
    var inst = asUTC - off1 * 60000;
    var off2 = offsetMinutes(zone, inst / 1000); // re-check: the guess may straddle a DST change
    if (off2 !== off1) inst = asUTC - off2 * 60000;
    return Math.floor(inst / 1000);
  }

  var RLTime = {
    ZONES: ZONES,
    resolveZone: resolveZone,
    fmt: fmt,
    fmtUtc: fmtUtc,
    fmtWithUtc: fmtWithUtc,
    toInput: toInput,
    fromInput: fromInput,
    offsetMinutes: offsetMinutes,
    // Plain mirror of the current selection so non-Alpine code can read it; the store keeps it fresh.
    current: { mode: 'utc', zone: 'UTC' },
  };
  global.RLTime = RLTime;

  // --- Alpine store + picker component (registered only if Alpine is present) ---
  document.addEventListener('alpine:init', function () {
    var cfg = global.RL_TZ || {};
    if (Array.isArray(cfg.zones)) RLTime.ZONES = ZONES = cfg.zones;
    var KEY = 'rl-tz';

    function store(kind) {
      try { return kind === 'local' ? localStorage : kind === 'session' ? sessionStorage : null; }
      catch (e) { return null; }
    }
    function load() {
      var s = store(cfg.persist);
      if (s) { try { var v = JSON.parse(s.getItem(KEY) || 'null'); if (v && v.mode) return v; } catch (e) {} }
      return { mode: cfg.mode || 'utc', zone: cfg.zone || 'UTC' };
    }

    Alpine.store('tz', {
      mode: 'utc',
      zone: 'UTC',
      withUtc: !!cfg.withUtc,
      init: function () {
        var v = load();
        this.mode = v.mode;
        this.zone = v.zone || 'UTC';
        RLTime.current = this.sel();
      },
      sel: function () { return { mode: this.mode, zone: this.zone }; },
      effective: function () { return RLTime.resolveZone(this.sel()); },
      set: function (mode, zone) {
        this.mode = mode;
        this.zone = zone || 'UTC';
        RLTime.current = this.sel();
        var s = store(cfg.persist);
        if (s) { try { s.setItem(KEY, JSON.stringify(this.sel())); } catch (e) {} }
        if (typeof cfg.onChange === 'function') cfg.onChange(this.sel());
      },
    });
  });

  // Backing component for TZ_PICKER_HTML (a Bootstrap dropdown).
  global.rlTzPicker = function () {
    return {
      zones: function () { return RLTime.ZONES; },
      label: function () {
        var s = this.$store.tz;
        if (s.mode === 'utc') return 'UTC';
        if (s.mode === 'browser') return 'Local · ' + RLTime.resolveZone(s.sel());
        return s.zone;
      },
      isActive: function (mode, zone) {
        var s = this.$store.tz;
        return s.mode === mode && (mode !== 'zone' || s.zone === zone);
      },
      pick: function (mode, zone) { this.$store.tz.set(mode, zone); },
    };
  };
})(window);
