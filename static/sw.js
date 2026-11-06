// The build id below is filled in by the server (version + hash of the frontend): every release
// gives a new cache name, so the new service worker installs and open pages reload.
const CACHE_NAME = 'notes-__BUILD_ID__';
const STATIC_ASSETS = ['/', '/manifest.json', '/static/logo.svg'];

self.addEventListener('install', (event) => {
    event.waitUntil(
        // cache: 'reload' bypasses the HTTP cache, so the new shell is really the new one
        caches.open(CACHE_NAME).then((cache) =>
            cache.addAll(STATIC_ASSETS.map((u) => new Request(u, { cache: 'reload' })))
        )
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(keys.filter((k) => k !== CACHE_NAME && k !== 'notes-images' && k !== 'notes-share-img').map((k) => caches.delete(k)))
        )
    );
    self.clients.claim();
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // ── MCP endpoint: never handled by the service worker ──
    if (url.pathname === '/mcp' || url.pathname.startsWith('/mcp/')) return;

    // ── Web Share Target ──
    if (url.pathname === '/share-target' && event.request.method === 'POST') {
        event.respondWith(
            (async () => {
                try {
                    const formData = await event.request.formData();
                    const title    = formData.get('title') || '';
                    const text     = formData.get('text')  || '';
                    const sharedUrl = formData.get('url')  || '';
                    const params = new URLSearchParams();
                    if (title)     params.set('share_title', title);
                    if (text)      params.set('share_text',  text);
                    if (sharedUrl) params.set('share_url',   sharedUrl);
                    const media = formData.get('media');
                    if (media && media instanceof File && media.size > 0) {
                        const imgCache = await caches.open('notes-share-img');
                        const buffer  = await media.arrayBuffer();
                        const imgResp = new Response(buffer, { headers: { 'Content-Type': media.type } });
                        await imgCache.put('/share-pending-image', imgResp);
                        params.set('share_has_image', '1');
                    }
                    return Response.redirect('/?' + params.toString(), 303);
                } catch (err) {
                    return Response.redirect('/', 303);
                }
            })()
        );
        return;
    }

    // ── Images: cache-first with network update (offline-friendly) ──
    if (url.pathname.startsWith('/api/images/')) {
        event.respondWith(
            caches.open('notes-images').then((cache) =>
                cache.match(event.request).then((cached) => {
                    const fetchPromise = fetch(event.request).then((response) => {
                        if (response.ok) cache.put(event.request, response.clone());
                        return response;
                    }).catch(() => cached);
                    return cached || fetchPromise;
                })
            )
        );
        return;
    }

    // ── API calls: network-first, fall back to cache ──
    // Exclude /api/sync — data is managed in IndexedDB, no need to double-cache
    // Exclude /api/tokens — MCP token list must always be fresh (network only)
    if (url.pathname.startsWith('/api/')) {
        if (url.pathname === '/api/sync' || url.pathname.startsWith('/api/tokens')) {
            event.respondWith(fetch(event.request));
            return;
        }
        event.respondWith(
            fetch(event.request).then((response) => {
                if (response.ok && event.request.method === 'GET') {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
                }
                return response;
            }).catch(() => caches.match(event.request))
        );
        return;
    }

    // Network-first for HTML pages, always revalidated with the server (never a stale HTTP cache)
    if (event.request.mode === 'navigate' || event.request.headers.get('accept')?.includes('text/html')) {
        const fresh = event.request.method === 'GET'
            ? new Request(event.request.url, { cache: 'no-cache', credentials: 'same-origin' })
            : event.request;
        event.respondWith(
            fetch(fresh).then((response) => {
                if (response.ok) {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
                }
                return response;
            }).catch(() => caches.match(event.request))
        );
        return;
    }

    // Cache-first for other static assets
    event.respondWith(
        caches.match(event.request).then((cached) => {
            const fetchPromise = fetch(event.request).then((response) => {
                if (response.ok) {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
                }
                return response;
            }).catch(() => cached);
            return cached || fetchPromise;
        })
    );
});
