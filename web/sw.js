// opgate service worker: shows opgate's web push notifications and runs their buttons. Approve opens the request
// page (the passkey decides); Deny and Revoke post to opgate in the background, like the same buttons on the
// pages, and opgate's next push shows the outcome.
const ICON = '/icon-192.png';
const BADGE = '/badge.png';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('push', e => {
  let m = {};
  try { m = e.data ? e.data.json() : {}; } catch (_) { m = { title: 'opgate', body: e.data ? e.data.text() : '' }; }
  e.waitUntil(show(m));
});

// opgate's tag names a notice (one per request, one per grant or key); `base` keeps it. A notice that should alert
// gets a fresh browser tag and replaces the older one itself: macOS (Chromium browsers) shows a replacement with the
// same tag silently, even with renotify. Quiet updates keep the tag and replace in place.
const withBase = async tag => (await self.registration.getNotifications()).filter(n => (n.data && n.data.base) === tag || n.tag === tag);

async function show(m) {
  if (m.kind === 'clear') {
    (await withBase(m.tag)).forEach(n => n.close());
    return;
  }
  const old = m.tag ? await withBase(m.tag) : [];
  const fresh = m.tag && !m.silent;
  const opts = {
    body: m.body || '', tag: fresh ? `${m.tag}#${Date.now()}` : (m.tag || undefined), data: { ...m, base: m.tag },
    icon: m.icon || ICON, badge: BADGE, silent: !!m.silent, requireInteraction: !!m.sticky, timestamp: m.ts || Date.now(),
    actions: (m.actions || []).map(a => ({ action: a.id, title: a.title })),
  };
  if (!fresh && old.length) opts.tag = old[0].tag; // quiet update: replace the shown one in place
  await self.registration.showNotification(m.title || 'opgate', opts);
  old.filter(n => n.tag !== opts.tag).forEach(n => n.close());
}

self.addEventListener('notificationclick', e => {
  const n = e.notification;
  const m = n.data || {};
  const a = (m.actions || []).find(x => x.id === e.action);
  n.close();
  e.waitUntil(a && a.post ? post(m, a) : open(a && a.url ? a.url : m.url));
});

async function post(m, a) {
  try {
    const r = await fetch(a.post, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      throw new Error(j.error || r.statusText);
    }
  } catch (err) {
    (await withBase(m.base || m.tag)).forEach(n => n.close());
    await self.registration.showNotification(`${a.title} failed`, {
      body: `${err.message}\nTap to open the page.`, tag: `${m.base || m.tag}#err`, icon: ICON, badge: BADGE,
      data: { url: m.url, base: m.base || m.tag },
    });
  }
}

async function open(url) {
  if (!url) url = '/';
  const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const c of all) {
    if (c.url === url && 'focus' in c) return c.focus();
  }
  return self.clients.openWindow(url);
}

// The browser renewed the subscription: tell opgate (it only accepts this for a subscription it knows).
self.addEventListener('pushsubscriptionchange', e => {
  e.waitUntil((async () => {
    const old = e.oldSubscription;
    let sub = e.newSubscription;
    if (!sub && old) sub = await self.registration.pushManager.subscribe(old.options);
    if (!old || !sub) return;
    const j = sub.toJSON();
    await fetch('/notify/resubscribe', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old: old.endpoint, endpoint: j.endpoint, p256dh: j.keys.p256dh, auth: j.keys.auth }),
    });
  })());
});
