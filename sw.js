// sw.js — Argira PWA. Recibe textos compartidos SIN red: el POST lo intercepta
// este service worker, guarda el texto en la caché local y redirige a la página.
const SHELL = 'argira-shell-v1';
const SHARE = 'argira-share';
const ROOT = new URL('./', self.registration.scope).href;

self.addEventListener('install', (e) => {
    self.skipWaiting();
    e.waitUntil(caches.open(SHELL)
        .then(c => c.addAll(['./', 'rules.js', 'share.js', 'manifest.webmanifest', 'icons/icon-192.png']))
        .catch(() => {}));
});
self.addEventListener('activate', (e) => {
    e.waitUntil(caches.keys()
        .then(ks => Promise.all(ks.filter(k => k !== SHELL && k !== SHARE).map(k => caches.delete(k))))
        .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
    const r = e.request;
    const u = new URL(r.url);
    if (r.method === 'POST' && u.origin === location.origin && u.href.split('?')[0] === ROOT) {
        e.respondWith((async () => {
            let text = '';
            try {
                const f = await r.formData();
                text = [f.get('title'), f.get('text'), f.get('url')].filter(Boolean).join('\n');
                const c = await caches.open(SHARE);
                await c.put('shared', new Response(text, { headers: { 'content-type': 'text/plain; charset=utf-8' } }));
            } catch (err) { /* sin texto */ }
            return Response.redirect(ROOT + '?shared=1', 303);
        })());
        return;
    }
    // Solo páginas propias; la API y las CDN no pasan por aquí.
    if (r.method !== 'GET' || u.origin !== location.origin) return;
    e.respondWith(fetch(r)
        .then(res => { const copy = res.clone(); caches.open(SHELL).then(c => c.put(r, copy)).catch(() => {}); return res; })
        .catch(() => caches.match(r)));
});
