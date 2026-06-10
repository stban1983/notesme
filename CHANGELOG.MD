# Changelog

## [1.5.1] - 2026-06-10 - Markdown import

- The note list panel now widens automatically to fit long folder names instead of truncating them.

## [1.5.0] - 2026-06-10 - Markdown import

### Added
- **Import Markdown notes.** A new import button (next to "new note") lets you bring in one or more `.md` / `.markdown` files at once — each file becomes a note, named after its filename, in the currently selected folder. Markdown is converted to rich text on the fly (headings, lists, tables, task lists, code blocks, quotes, links).
- **Image import.** Select your `.md` files together with their referenced images and they'll be uploaded and re-hosted automatically. Images matched by filename.

### Security
- Imported content goes through the same defenses as everything else: client-side DOMPurify, then server-side nh3 sanitization and at-rest encryption. The new `marked` Markdown library is loaded from CDN with a Subresource Integrity (SRI) hash.

## [1.4.0] - 2026-06-02 - Security hardening & maintenance

### Security
- Dependencies upgraded to current releases (notably `python-multipart` 0.0.9 → 0.0.30, which fixes a known DoS advisory; also FastAPI, uvicorn, cryptography, PyJWT, argon2-cffi, nh3).
- Subresource Integrity (SRI) hashes added to the DOMPurify and Prism CDN scripts — protects against a compromised CDN tampering with the client-side XSS sanitizer.
- Folder/note ownership is now validated server-side: a note or sub-folder can no longer be attached to another user's folder, and folder moves that would create a cycle are rejected.
- Path-traversal guard on image serving hardened (`commonpath` instead of prefix match).
- Startup warnings when `SECRET_KEY`/`ENCRYPTION_KEY` are missing or the default admin password is still in use.

### Changed
- `USERNAME` environment variable renamed to `ADMIN_USERNAME` to avoid collision with the OS-provided `USERNAME` variable. `USERNAME` is still honored as a fallback, so existing setups keep working.

### Internal
- Login rate-limiter no longer grows unbounded in memory; search result sorting simplified to a single pass; dead imports removed.

## [1.3.1] - 2026-18-05 - migrate to last LTS python alpine image

- python:3.12-alpine to python:3.13-alpine


## [1.3.0] - 2026-22-04 - Enhanced text editor

- Add more styles
- Fix: changinf format is now fixed

## [1.2.3] - 2026-17-04 - Fix refreshing notes

- Fix: Removed list blinking while typing.
- Local note update after saving (without server reload); fadeIn animation disabled on silent re-renderers.


## [1.2.2] - 2026-25-03 - Functionality and fix Update

- Add search term highlighting inside editor content
- Fix collapse folder

Don't forget to clear your cache! 


## [1.2.1] - 2026-12-03 - Functionality and fix Update

- You can sort your notes!


## [1.2.0] - 2026-09-03 - Functionality and fix Update

Big updates today:

- Dark theme more visible
- Tasks were disapearing when closing a note
- Some french text had been deleted
- and the big one: The Markdown is now supported !



## [1.1.0] - 2026-03-03 - Security Update

This update focuses on hardening the application against common web attacks.

### Server-side content cleaning

All note content, titles, and folder names are now sanitized on the server before being saved. This blocks malicious code injection (XSS) even if someone bypasses the web interface (e.g. using Postman or a script). It use nh3, a fast Rust-based HTML sanitizer — your formatting (bold, lists, links, images, tables...) is preserved, but dangerous elements like <script> or <iframe> are stripped out.

### Smarter rate limiting behind a proxy

Login attempt tracking now correctly identifies users by their real IP address when the app runs behind a reverse proxy (Nginx, Traefik, etc.). Previously, all users behind a proxy shared the same counter, which could lock everyone out. Set TRUSTED_PROXY_COUNT=1 in your environment to activate this.

### Safer HTML export

Exported HTML files now go through the same sanitization process, so any previously stored content can't execute scripts when opened in a browser.

### Security headers

Every response now includes protective HTTP headers:

- Content-Security-Policy — controls which scripts, styles and fonts can load
- X-Content-Type-Options — prevents browsers from guessing file types
- X-Frame-Options — blocks the app from being embedded in iframes (anti-clickjacking)
- Referrer-Policy — limits information sent to other sites

### Minor fix
Replaced the deprecated apple-mobile-web-app-capable meta tag with the current mobile-web-app-capable.


### New environment variable
TRUSTED_PROXY_COUNT : Number of trusted reverse proxies in front of the app. Set to 1 if behind Nginx/Traefik.
