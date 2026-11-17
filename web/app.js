// opgate approval page: WebAuthn get()/create() with the server's options, posted back as standard JSON.
// ?go=approve (notification button) starts the passkey prompt at once; ?go=deny denies at once.
const b64u = {
  dec: s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0)),
  enc: b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
};
const $ = id => document.getElementById(id);
const post = async (url, body) => {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
};
const desktop = matchMedia('(min-width: 860px)');
const say = t => { if ($('msg')) $('msg').textContent = t; };

const req = $('req');

// ---------- commands: shown as code, one step per line
// fmtCmd turns a shell command into lines of highlighted parts: each step (after &&, ||, ;, | or a newline) starts a
// line, the program is bold, flags dim, quoted text and op:// references coloured, heredocs stay as written.
// opgate's --reason (the page shows it above) becomes "…"; home and Claude Code's scratch folders are shortened.
// Display only: the full command lines stay in the process chain.
const shortPath = w => w
  .replace(/\/(?:private\/)?tmp\/claude-\d+\/[^/\s'"]+\/[0-9a-f-]{36}\//g, '…/')
  .replace(/\/Users\/[^/\s'"]+(?=\/|$|["'\s])/g, '~');
function shellLex(src) {
  const toks = []; // {k: 'w'|'op'|'nl'|'here'|'cmt', v}
  let i = 0, w = '', q = '', depth = 0, pendingHere = [];
  const flush = () => { if (w) { toks.push({ k: 'w', v: w }); const m = /^\d*<<-?\s*['"]?([\w.-]+)['"]?$/.exec(w); if (m) pendingHere.push(m[1]); } w = ''; };
  while (i < src.length) {
    const c = src[i], two = src.slice(i, i + 2);
    if (q) { // inside quotes: everything belongs to the word
      w += c; i++;
      if (c === '\\' && q === '"' && i < src.length) { w += src[i++]; continue; }
      if (c === q) q = '';
      continue;
    }
    if (c === "'" || c === '"') { q = c; w += c; i++; continue; }
    if (c === '\\' && i + 1 < src.length) { w += two; i += 2; continue; }
    if (two === '$(') { depth++; w += two; i += 2; continue; }
    if (c === '(' ) { depth++; w += c; i++; continue; }
    if (c === ')' && depth > 0) { depth--; w += c; i++; continue; }
    if (depth > 0) { w += c; i++; continue; }
    if (c === '#' && !w) { const e = src.indexOf('\n', i); const end = e < 0 ? src.length : e; toks.push({ k: 'cmt', v: src.slice(i, end) }); i = end; continue; }
    if (c === '\n') {
      flush(); toks.push({ k: 'nl', v: '' }); i++;
      for (const delim of pendingHere.splice(0)) { // the heredoc's lines, as written, up to its delimiter
        while (i < src.length) {
          const e = src.indexOf('\n', i), end = e < 0 ? src.length : e, line = src.slice(i, end);
          i = end + 1;
          toks.push({ k: 'here', v: line });
          if (line.trim() === delim) break;
        }
        toks.push({ k: 'nl', v: '' });
      }
      continue;
    }
    if (c === ' ' || c === '\t') { flush(); i++; continue; }
    if (two === '&&' || two === '||') { flush(); toks.push({ k: 'op', v: two }); i += 2; continue; }
    if (c === ';' || (c === '|' && src[i + 1] !== '&') || (c === '&' && !/[<>]$/.test(w) && src[i + 1] !== '>')) { flush(); toks.push({ k: 'op', v: c }); i++; continue; }
    w += c; i++;
  }
  flush();
  return toks;
}
function fmtCmd(src) {
  const frag = document.createDocumentFragment();
  let line = null, first = true, elide = false;
  const newLine = () => { line = document.createElement('span'); line.className = 'ln'; frag.appendChild(line); first = true; elide = false; };
  newLine();
  const add = (cls, text, title) => {
    if (line.childNodes.length) line.appendChild(document.createTextNode(' '));
    const s = document.createElement('span');
    if (cls) s.className = cls;
    s.textContent = text;
    if (title) s.title = title;
    line.appendChild(s);
  };
  let prog = '';
  for (const t of shellLex(src)) {
    if (t.k === 'nl') { newLine(); prog = ''; continue; }
    if (t.k === 'here') { newLine(); add('str', t.v); continue; }
    if (t.k === 'cmt') { add('cmt', t.v); continue; }
    if (t.k === 'op') {
      if (t.v === '&') { add('op', t.v); continue; }
      newLine(); add('op', t.v); prog = ''; continue;
    }
    const v = t.v;
    if (elide) { add('elide', '…', 'the reason, shown above'); elide = false; continue; }
    if (/^(--reason|OPGATE_REASON)=/.test(v)) { add('flag', v.split('=')[0] + '='); line.lastChild.after(Object.assign(document.createElement('span'), { className: 'elide', textContent: '…', title: 'the reason, shown above' })); continue; }
    if (first && /^[A-Za-z_]\w*=/.test(v)) { add('var', shortPath(v)); continue; }
    if (first) {
      first = false;
      const base = v.startsWith('/') && !/\s/.test(v) ? v.slice(v.lastIndexOf('/') + 1) : v;
      prog = base;
      add('prog', shortPath(base), base !== v ? v : '');
      continue;
    }
    if (v === '--reason' && /^(opgate|op)$/.test(prog)) { add('flag', v); elide = true; continue; }
    if (/^\d*(<<?|>>?|>\||&>)/.test(v)) { add('op', shortPath(v)); continue; }
    if (/op:\/\//.test(v)) { add('ref', v); continue; }
    if (v.startsWith('-')) { add('flag', shortPath(v)); continue; }
    if (/^['"$]/.test(v)) { add('str', shortPath(v)); continue; }
    add('', shortPath(v));
  }
  return frag;
}
// fmtInto replaces an element's command text with the formatted version (once)
const fmtInto = el => {
  if (!el || el.dataset.done) return;
  el.dataset.done = '1';
  el.replaceChildren(fmtCmd(el.textContent.trim()));
  el.classList.add('fmt');
};
document.querySelectorAll('[data-cmd]').forEach(fmtInto);
// "tap to expand" only where there is more to see
const clamp = box => {
  const t = box.querySelector('.text');
  const more = t && t.scrollHeight > t.clientHeight + 2;
  box.classList.toggle('clamped', more);
  const hint = box.nextElementSibling?.querySelector('.more');
  if (hint) hint.hidden = !more;
};
document.querySelectorAll('.cmd').forEach(clamp);

// the service worker shows opgate's pushes (sw.js); every page registers it so the installed app has it
const swReady = 'serviceWorker' in navigator
  ? navigator.serviceWorker.register('/sw.js').then(() => navigator.serviceWorker.ready).catch(() => null)
  : Promise.resolve(null);
// closeNotices removes this request's notification on this device once it is decided here
const closeNotices = tag => swReady.then(reg => reg && reg.getNotifications())
  .then(ns => (ns || []).filter(n => n.tag === tag || (n.data && n.data.base) === tag).forEach(n => n.close())).catch(() => {});

// countdown pill; at zero the request is gone
let expired = false;
const timer = $('timer');
if (timer) {
  const until = Number(timer.dataset.expires);
  const tick = () => {
    const s = Math.max(0, Math.round((until - Date.now()) / 1000));
    $('left').textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
    timer.classList.toggle('low', s < 60);
    if (s === 0 && !expired && $('req') && !document.body.classList.contains('decided')) { expired = true; result('no', 'Expired', 'Nobody decided in time.'); }
  };
  tick();
  setInterval(tick, 1000);
}

// tap-to-expand for the command and the process chain
$('cmd')?.addEventListener('click', e => e.currentTarget.classList.toggle('open'));
document.querySelectorAll('.chain code').forEach(c => c.addEventListener('click', () => c.classList.toggle('open')));
if ($('details') && desktop.matches) $('details').open = true;

// result shows the outcome and tries to close the tab. Browsers only allow that for a tab they opened for a
// notification with nothing to go back to; otherwise the tab stays and the Overview button below the outcome leads on.
function result(kind, title, text) {
  if (req) closeNotices('opgate-' + req.dataset.id);
  const g = $('glyph');
  if (g) g.setAttribute('d', kind === 'ok' ? 'M30 47l11 11 22-24' : 'M33 33l26 26M59 33L33 59');
  $('result').className = 'result ' + kind;
  $('rtitle').textContent = title;
  if (text) $('rtext').textContent = text;
  document.body.classList.add('decided');
  setTimeout(() => {
    window.close();
    setTimeout(() => { $('rsub').textContent = 'You can close this tab.'; }, 300);
  }, 1400);
}

const busy = (btn, on) => {
  document.querySelectorAll('.bar .btn').forEach(b => (b.disabled = on));
  btn?.classList.toggle('busy', on);
};

// live runs check() when opgate reports a change (server-sent events from /events), when the tab comes back into
// view, and every 15 s while the stream is down. Hidden tabs close their stream (phones, the server's cap).
function live(check) {
  let es = null, t = 0;
  const run = () => { clearTimeout(t); t = setTimeout(() => check().catch(() => {}), 250); };
  const open = () => {
    if (es || !window.EventSource) return;
    es = new EventSource('/events');
    es.addEventListener('change', run);
  };
  const close = () => { es?.close(); es = null; };
  document.addEventListener('visibilitychange', () => { if (document.hidden) close(); else { open(); run(); } });
  addEventListener('pageshow', e => { if (e.persisted) { open(); run(); } });
  if (!document.hidden) open();
  setInterval(() => { if (!document.hidden && es?.readyState !== EventSource.OPEN) run(); }, 15000);
}
const getJSON = async url => (await fetch(url, { cache: 'no-store' })).json();
// stale shows the "Refresh" pill: the page changed, but reloading now would lose what you're doing
const stale = () => { if ($('stale')) $('stale').hidden = false; };
$('stale')?.addEventListener('click', () => location.reload());

async function approve(id, dur) {
  const { publicKey: o } = await post(`/r/${id}/options`);
  o.challenge = b64u.dec(o.challenge);
  (o.allowCredentials || []).forEach(c => (c.id = b64u.dec(c.id)));
  const c = await navigator.credentials.get({ publicKey: o });
  await post(`/r/${id}/approve?dur=${encodeURIComponent(dur)}`, {
    id: c.id, rawId: b64u.enc(c.rawId), type: c.type,
    response: {
      clientDataJSON: b64u.enc(c.response.clientDataJSON),
      authenticatorData: b64u.enc(c.response.authenticatorData),
      signature: b64u.enc(c.response.signature),
      userHandle: c.response.userHandle ? b64u.enc(c.response.userHandle) : undefined,
    },
  });
}

if (req) {
  const id = req.dataset.id;
  const durValue = () => document.querySelector('input[name=dur]:checked')?.value || '';
  const durLabel = () => document.querySelector('input[name=dur]:checked + label')?.textContent || '';
  const isSSH = document.body.classList.contains('k-ssh');
  let deciding = false; // this page's own decision is on its way: its answer shows the outcome
  // decided elsewhere (another tab, the phone, a notification button), expired, or the agent gave up
  const check = async () => {
    if (deciding || document.body.classList.contains('decided')) return;
    const s = await getJSON(`/r/${id}/state`);
    const t = req.dataset.title;
    if (s.status === 'pending') return;
    if (s.status === 'approved') result('ok', 'Approved', `${t} · approved elsewhere${s.by ? ` (passkey “${s.by}”)` : ''}`);
    else if (s.status === 'denied') result('no', 'Denied', `${t} · denied elsewhere`);
    else if (s.status === 'expired') { expired = true; result('no', 'Expired', 'Nobody decided in time.'); }
    else result('no', 'Ended', s.status === 'error' ? `${t} · the agent stopped waiting, or it failed` : 'This request is no longer open.');
  };
  live(check);
  const doApprove = async () => {
    if (expired) return;
    deciding = true;
    busy($('approve'), true);
    say('');
    const dur = durValue();
    try {
      await approve(id, dur);
      const label = durLabel();
      const text = isSSH ? `${req.dataset.title} · loaded for ${label}`
        : dur && dur !== '0s' ? `${req.dataset.title} · same again for ${label}` : req.dataset.title;
      result('ok', 'Approved', text);
    } catch (err) {
      busy($('approve'), false);
      // a passkey prompt started without a tap can be refused by the browser: the button still works
      say(err.name === 'NotAllowedError' ? 'Passkey cancelled. Tap Approve to try again.' : 'Not approved: ' + err.message);
      deciding = false;
      check().catch(() => {});
    }
  };
  const doDeny = async () => {
    if (expired) return;
    deciding = true;
    busy($('deny'), true);
    try {
      await post(`/r/${id}/deny`);
      result('no', 'Denied', req.dataset.title);
    } catch (err) {
      busy($('deny'), false);
      say('Could not deny: ' + err.message);
      deciding = false;
      check().catch(() => {});
    }
  };
  $('approve').addEventListener('click', doApprove);
  $('deny').addEventListener('click', doDeny);
  document.addEventListener('keydown', e => {
    if (document.body.classList.contains('decided') || e.target.closest?.('input, textarea, button, a')) return;
    if (e.key === 'Enter') { e.preventDefault(); doApprove(); }
    if (e.key === 'Escape') { e.preventDefault(); doDeny(); }
  });
  // from a phone notification: straight to the fingerprint. On a desktop only from opgate's own push (its Approve
  // link carries a token): a link an agent opens on the Mac must never start a passkey prompt by itself.
  if (req.dataset.go === 'approve' && (req.dataset.auto === '1' || !desktop.matches && matchMedia('(pointer: coarse)').matches)) doApprove();
  if (req.dataset.go === 'deny') doDeny();
}

const en = $('enroll');
if (en) {
  en.addEventListener('click', async () => {
    busy(en, true);
    say('');
    try {
      const id = en.dataset.id, k = encodeURIComponent(en.dataset.k);
      const { publicKey: o } = await post(`/enroll/${id}/options?k=${k}`);
      o.challenge = b64u.dec(o.challenge);
      o.user.id = b64u.dec(o.user.id);
      (o.excludeCredentials || []).forEach(c => (c.id = b64u.dec(c.id)));
      const c = await navigator.credentials.create({ publicKey: o });
      await post(`/enroll/${id}/finish?k=${k}`, {
        id: c.id, rawId: b64u.enc(c.rawId), type: c.type,
        response: {
          clientDataJSON: b64u.enc(c.response.clientDataJSON),
          attestationObject: b64u.enc(c.response.attestationObject),
          transports: c.response.getTransports ? c.response.getTransports() : [],
        },
      });
      en.classList.remove('busy');
      en.querySelector('span:last-child').textContent = 'Registered · add the entry to 1Password';
    } catch (err) {
      busy(en, false);
      say('Failed: ' + err.message);
    }
  });
}

// activity page: revoke (and stop running ssh sessions); ?go=revoke from the notification revokes at once
const act = $('act');
if (act) {
  const tag = act.dataset.tag;
  const doRevoke = async stop => {
    const btn = $(stop ? 'stop' : 'revoke');
    busy(btn, true);
    try {
      const r = await post(`/u/${tag}/${stop ? 'stop' : 'revoke'}`);
      result('no', 'Revoked', act.dataset.title + (r.stopped ? ` · ${r.stopped} running session${r.stopped > 1 ? 's' : ''} stopped` : ''));
    } catch (err) {
      busy(btn, false);
      if ($('msg2')) $('msg2').textContent = 'Could not revoke: ' + err.message;
    }
  };
  $('revoke')?.addEventListener('click', () => doRevoke(false));
  $('restore')?.addEventListener('click', async () => {
    busy($('restore'), true);
    try {
      const r = await post(`/u/${tag}/restore`);
      location.href = r.url; // the normal approval page: passkey required
    } catch (err) {
      busy($('restore'), false);
      if ($('msg2')) $('msg2').textContent = 'Could not ask: ' + err.message;
    }
  });
  $('stop')?.addEventListener('click', () => doRevoke(true));
  // new uses or a revoke elsewhere: reload, unless something is open or a button is busy
  live(async () => {
    if (document.body.classList.contains('decided')) return;
    const s = await getJSON(`/u/${tag}/state`);
    if (s.found && s.count === Number(act.dataset.count) && String(s.revoked) === act.dataset.revoked) return;
    if (document.querySelector('details[open], .open, .btn.busy')) stale(); else location.reload();
  });
  document.querySelectorAll('.uses .cmd').forEach(c => c.addEventListener('click', () => c.classList.toggle('open')));
  if (act.dataset.go === 'revoke' && $('revoke')) doRevoke(false);
}

// overview tabs: History (default), Credentials, 30 days; the tab is kept in the address (#creds), so a reload stays
// on it, and a link to something inside a tab (a credential from Needs attention) opens that tab
const tabs = $('tabs');
if (tabs) {
  const panels = [...document.querySelectorAll('.panel[data-tab]')];
  const show = name => {
    if (!panels.some(p => p.dataset.tab === name)) name = 'history';
    tabs.querySelectorAll('[data-tab]').forEach(a => { const on = a.dataset.tab === name; a.classList.toggle('on', on); a.setAttribute('aria-selected', on); });
    panels.forEach(p => { p.hidden = p.dataset.tab !== name; });
  };
  const fromHash = () => {
    const h = decodeURIComponent(location.hash.slice(1));
    const el = h ? document.getElementById(h) : null; // h && … gave "" without a hash, and "".closest threw
    const panel = el?.closest('.panel');
    show(panel ? panel.dataset.tab : h);
    if (panel) el.scrollIntoView({ block: 'center' });
  };
  tabs.addEventListener('click', e => {
    const a = e.target.closest('[data-tab]');
    if (!a) return;
    e.preventDefault();
    show(a.dataset.tab);
    history.replaceState(null, '', '#' + a.dataset.tab);
  });
  addEventListener('hashchange', fromHash);
  fromHash();
}

// History tab: the server searches the whole audit log and sends 20 events at a time (/history/items)
const events = $('events');
const hist = { page: 1, busy: () => false };
if (events) {
  const q = $('q'), ftype = $('ftype'), fstatus = $('fstatus'), fdir = $('fdir'), routine = $('routine'), filt = $('filt');
  try { routine.checked = localStorage.getItem('opgate.routine') === '1'; } catch {}
  const filtered = () => !!(ftype.value || fstatus.value || fdir.value || routine.checked);
  hist.busy = () => !!(q.value.trim() || ftype.value || fstatus.value || fdir.value || hist.page > 1 || events.querySelector('li.open') || document.activeElement === q);
  let seq = 0;
  const load = async () => {
    const n = ++seq;
    const p = new URLSearchParams({ q: q.value.trim(), type: ftype.value, status: fstatus.value, dir: fdir.value,
      routine: routine.checked ? '1' : '', page: hist.page });
    try {
      const r = await fetch('/history/items?' + p, { cache: 'no-store' });
      const j = await r.json();
      if (n !== seq) return; // a newer search is on its way
      if (j.error) throw new Error(j.error);
      events.innerHTML = j.html;
      hist.page = j.page;
      $('count').textContent = j.label;
      $('prev').disabled = j.page <= 1;
      $('next').disabled = j.page >= j.pages;
    } catch (e) {
      if (n === seq) $('count').textContent = 'Could not load: ' + e.message;
    }
  };
  const again = () => { hist.page = 1; filt.classList.toggle('on', filtered()); load(); };
  let wait;
  q.addEventListener('input', () => { clearTimeout(wait); wait = setTimeout(again, 250); });
  [ftype, fstatus, fdir, routine].forEach(el => el.addEventListener('change', again));
  routine.addEventListener('change', () => { try { localStorage.setItem('opgate.routine', routine.checked ? '1' : '0'); } catch {} });
  filt.addEventListener('click', () => {
    const open = $('hfilters').hidden;
    $('hfilters').hidden = !open;
    filt.setAttribute('aria-expanded', open);
  });
  const turn = d => {
    hist.page += d;
    load().then(() => { const top = $('tabs').getBoundingClientRect().top; if (top < 0) $('tabs').scrollIntoView(); });
  };
  $('prev').addEventListener('click', () => turn(-1));
  $('next').addEventListener('click', () => turn(1));
  // a tap opens the event: the whole command, formatted, and where it ran (selecting text inside doesn't close it)
  events.addEventListener('click', e => {
    const li = e.target.closest('li.ev');
    if (!li || e.target.closest('a') || (e.target.closest('.full') && getSelection().toString())) return;
    if (e.target.closest('.full') && li.classList.contains('open')) return;
    li.querySelectorAll('[data-lazy-cmd]').forEach(fmtInto);
    li.classList.toggle('open');
  });
  if (routine.checked) again();
}

// overview: unlock the credential details with a passkey (10 min in this browser), lock again, load a revoked key
const ovSay = t => { if ($('msg')) $('msg').textContent = t; };
$('unlock')?.addEventListener('click', async e => {
  const btn = e.currentTarget;
  btn.disabled = true;
  ovSay('');
  try {
    const { id, publicKey: o } = await post('/unlock/options');
    o.challenge = b64u.dec(o.challenge);
    (o.allowCredentials || []).forEach(c => (c.id = b64u.dec(c.id)));
    const c = await navigator.credentials.get({ publicKey: o });
    await post(`/unlock/finish?id=${encodeURIComponent(id)}`, {
      id: c.id, rawId: b64u.enc(c.rawId), type: c.type,
      response: {
        clientDataJSON: b64u.enc(c.response.clientDataJSON),
        authenticatorData: b64u.enc(c.response.authenticatorData),
        signature: b64u.enc(c.response.signature),
        userHandle: c.response.userHandle ? b64u.enc(c.response.userHandle) : undefined,
      },
    });
    location.reload();
  } catch (err) {
    btn.disabled = false;
    ovSay(err.name === 'NotAllowedError' ? 'Passkey cancelled.' : 'Not unlocked: ' + err.message);
  }
});
$('lock')?.addEventListener('click', async () => { await post('/lock').catch(() => {}); location.reload(); });
document.querySelectorAll('.restore').forEach(btn => btn.addEventListener('click', async () => {
  btn.disabled = true;
  try {
    const r = await post('/restore', { ref: btn.dataset.ref });
    location.href = r.url; // the normal approval page: passkey required
  } catch (err) {
    btn.disabled = false;
    ovSay('Could not ask: ' + err.message);
  }
}));

// overview: dismiss past failures, revoke from the list, live countdowns, filter, and reload when something changes
const ovBusy = { on: false };
document.querySelectorAll('.dismiss').forEach(btn => btn.addEventListener('click', async () => {
  btn.disabled = true;
  try {
    await post('/dismiss', { key: btn.dataset.key });
    location.reload();
  } catch (err) {
    btn.disabled = false;
    ovSay('Could not dismiss: ' + err.message);
  }
}));
document.querySelectorAll('.revoke[data-tag]').forEach(btn => btn.addEventListener('click', async () => {
  const stop = btn.dataset.stop === '1';
  const what = stop ? `Revoke ${btn.dataset.title} and end the ssh sessions that use it?` : `Revoke ${btn.dataset.title}?`;
  const daily = btn.dataset.daily === '1' ? '\n\nWhatever uses this key (git signing, ssh) stops until you load it again with your passkey.' : '';
  if (!confirm(what + daily)) return;
  ovBusy.on = true;
  btn.disabled = true;
  try {
    await post(`/u/${btn.dataset.tag}/${stop ? 'stop' : 'revoke'}`);
    location.reload();
  } catch (err) {
    ovBusy.on = false;
    btn.disabled = false;
    ovSay('Could not revoke: ' + err.message);
  }
}));
const fmtLeft = until => {
  const s = Math.round((until - Date.now()) / 1000);
  const hm = new Date(until).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
  if (s <= 0) return null;
  return s < 60 ? `until ${hm} · under a minute left` : `until ${hm} · ${Math.ceil(s / 60)} min left`;
};
const tickLeft = () => document.querySelectorAll('.left[data-until]').forEach(el => {
  const t = fmtLeft(Number(el.dataset.until));
  if (t) el.textContent = t;
  else { el.textContent = 'ended'; el.classList.add('ended'); }
});
if (document.querySelector('.left[data-until]')) { tickLeft(); setInterval(tickLeft, 15000); }
const cq = $('cq');
if (cq) {
  const rows = [...document.querySelectorAll('#allcreds > li')];
  cq.addEventListener('input', () => {
    const q = cq.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    let shown = 0;
    rows.forEach(li => { const ok = q.every(w => li.dataset.text.includes(w)); li.hidden = !ok; if (ok) shown++; });
    $('cnone').hidden = shown > 0;
  });
}
if (document.body.dataset.sig) {
  // reload when the page would change (new request, revoke elsewhere, new failure); while you're doing something
  // (searching or paging the history, an event open, typing in a filter) the Refresh pill shows instead
  const sig = document.body.dataset.sig;
  live(async () => {
    const j = await getJSON('/overview/state');
    if (!j.sig || j.sig === sig) return;
    if (ovBusy.on || hist.busy() || document.activeElement === cq || $('unlock')?.disabled) stale(); else location.reload();
  });
}

// notifications page: turn notifications on for this browser, levels per device, rename, remove, test
const notify = $('notify');
if (notify) {
  const unlocked = notify.dataset.unlocked === '1';
  if (!unlocked) document.body.classList.add('locked');
  const nSay = t => { if ($('msg')) $('msg').textContent = t; };
  const needUnlock = () => nSay('Unlock with your passkey first (the button above).');
  const hashOf = async s => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))]
    .slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
  const ua = navigator.userAgent;
  const mobile = navigator.userAgentData ? navigator.userAgentData.mobile : /Android|iPhone|iPad/.test(ua);
  const guessName = () => {
    const brands = (navigator.userAgentData?.brands || []).map(b => b.brand);
    const browser = /Edg\//.test(ua) ? 'Edge' : brands.includes('Google Chrome') ? 'Chrome' : brands.includes('Brave') ? 'Brave'
      : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) && !/Chrome\//.test(ua) ? 'Safari' : 'browser';
    const where = /Android/.test(ua) ? 'Phone' : /iPhone|iPad/.test(ua) ? 'iPhone' : /Mac OS X|Macintosh/.test(ua) ? 'Mac' : 'Computer';
    return `${where} · ${browser}`;
  };
  const state = $('thisstate'), subBtn = $('subscribe');
  const devices = [...document.querySelectorAll('.dev')];
  const subscribe = async () => {
    if (!unlocked) return needUnlock();
    subBtn.disabled = true;
    nSay('');
    try {
      if (await Notification.requestPermission() !== 'granted') throw new Error('notifications are blocked for this site in the browser settings');
      const reg = await swReady;
      if (!reg) throw new Error('no service worker');
      const key = b64u.dec(notify.dataset.key);
      let sub = await reg.pushManager.getSubscription();
      if (sub && sub.options.applicationServerKey &&
        b64u.enc(sub.options.applicationServerKey) !== b64u.enc(key)) { await sub.unsubscribe(); sub = null; }
      if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      const j = sub.toJSON();
      const known = devices.find(d => d.dataset.hash === state.dataset.hash);
      const name = known ? known.dataset.name : (prompt('Name for this device', guessName()) || guessName());
      const r = await post('/notify/subscribe', { endpoint: j.endpoint, p256dh: j.keys.p256dh, auth: j.keys.auth, name, mobile });
      await post('/notify/test', { id: r.id });
      location.reload();
    } catch (err) {
      subBtn.disabled = false;
      nSay('Not turned on: ' + err.message);
    }
  };
  subBtn.addEventListener('click', subscribe);
  (async () => {
    if (!('serviceWorker' in navigator) || !('PushManager' in window) || !window.isSecureContext) {
      state.textContent = 'This browser can’t get push notifications here. Open the approval page at its https address in Chrome (phone) or a Chromium browser.';
      return;
    }
    if (!notify.dataset.key) { state.textContent = 'Web push isn’t available (see above).'; return; }
    const reg = await swReady;
    const sub = reg && await reg.pushManager.getSubscription();
    const hash = sub ? await hashOf(sub.endpoint) : '';
    state.dataset.hash = hash;
    const mine = hash && devices.find(d => d.dataset.hash === hash);
    if (mine) {
      mine.classList.add('this');
      mine.querySelector('.thisbadge').hidden = false;
      if (mine.classList.contains('gone')) {
        state.textContent = 'This device’s subscription ended. Turn it on again (keeps its settings).';
        subBtn.textContent = 'Turn on again';
        subBtn.hidden = false;
      } else if (Notification.permission !== 'granted') {
        state.textContent = 'Turned on, but the browser blocks notifications for this site now. Allow them in the site settings.';
      } else {
        state.textContent = `On: ${mine.dataset.name}. Its settings are marked below.`;
      }
      return;
    }
    state.textContent = Notification.permission === 'denied'
      ? 'Notifications are blocked for this site in the browser settings. Allow them, then turn them on here.'
      : 'Not turned on in this browser.';
    subBtn.hidden = false;
  })();

  // levels and fallbacks save on change
  notify.querySelectorAll('.seg input').forEach(inp => inp.addEventListener('change', async () => {
    const group = [...notify.querySelectorAll(`input[name="${inp.name}"]`)];
    const prev = group.find(i => i.defaultChecked);
    if (!unlocked) { if (prev) prev.checked = true; return needUnlock(); }
    nSay('');
    try {
      const dev = inp.closest('.dev');
      await post('/notify/level', { id: dev.dataset.id, cat: inp.name.split('-').pop(), level: inp.value });
      group.forEach(i => (i.defaultChecked = i === inp));
    } catch (err) {
      if (prev) prev.checked = true;
      nSay('Not saved: ' + err.message);
    }
  }));
  devices.forEach(dev => {
    const id = dev.dataset.id;
    const run = async (btn, fn, ok) => {
      if (!unlocked) return needUnlock();
      btn.disabled = true;
      nSay('');
      try { await fn(); if (ok) ok(); } catch (err) { nSay(err.message); }
      btn.disabled = false;
    };
    const test = dev.querySelector('.test');
    test.addEventListener('click', () => run(test, () => post('/notify/test', { id }), () => nSay(`Test sent to ${dev.dataset.name}.`)));
    const ren = dev.querySelector('.rename');
    ren.addEventListener('click', () => {
      if (!unlocked) return needUnlock();
      const name = prompt('Name', dev.dataset.name);
      if (name && name !== dev.dataset.name) run(ren, () => post('/notify/rename', { id, name }), () => location.reload());
    });
    const rm = dev.querySelector('.remove');
    rm.addEventListener('click', () => {
      if (!unlocked) return needUnlock();
      if (confirm(`Stop notifications on ${dev.dataset.name}?`)) run(rm, () => post('/notify/remove', { id }), () => location.reload());
    });
  });
}
