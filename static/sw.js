const CACHE_NAME = 'notes-v9';
const STATIC_ASSETS = ['/', '/manifest.json', '/static/logo.svg'];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
        )
    );
    self.clients.claim();
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // ── Web Share Target ──────────────────────────────────────────────────────
    // Intercept the POST sent by Android/Chrome when user shares to NotesMe.
    // Extract text data and redirect to the app with query params so the page
    // can create a note from the shared content (no server changes needed).
    if (url.pathname === '/share-target' && event.request.method === 'POST') {
        event.respondWith(
            (async () => {
                try {
                    const formData = await event.request.formData();
                    const title    = formData.get('title') || '';
                    const text     = formData.get('text')  || '';
                    const sharedUrl = formData.get('url')  || '';

                    // Build redirect URL with share params
                    const params = new URLSearchParams();
                    if (title)     params.set('share_title', title);
                    if (text)      params.set('share_text',  text);
                    if (sharedUrl) params.set('share_url',   sharedUrl);

                    // Check if a file (image) was shared
                    const media = formData.get('media');
                    if (media && media instanceof File && media.size > 0) {
                        // Store image in cache under a known key so the app can pick it up
                        const imgCache = await caches.open('notes-share-img');
                        const buffer  = await media.arrayBuffer();
                        const imgResp = new Response(buffer, { headers: { 'Content-Type': media.type } });
                        await imgCache.put('/share-pending-image', imgResp);
                        params.set('share_has_image', '1');
                    }

                    return Response.redirect('/?' + params.toString(), 303);
                } catch (err) {
                    // On any error fall back to the app root
                    return Response.redirect('/', 303);
                }
            })()
        );
        return;
    }

    // Network-first for API calls
    if (url.pathname.startsWith('/api/')) {
        event.respondWith(
            fetch(event.request).catch(() => caches.match(event.request))
        );
        return;
    }

    // Network-first for HTML pages (avoid serving stale UI)
    if (event.request.mode === 'navigate' || event.request.headers.get('accept')?.includes('text/html')) {
        event.respondWith(
            fetch(event.request).then((response) => {
                if (response.ok) {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
                }
                return response;
            }).catch(() => caches.match(event.request))
        );
        return;
    }

    // Cache-first for other static assets (fonts, icons)
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
