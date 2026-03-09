# Changelog

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
