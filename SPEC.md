# Potpuri Specification

## Product Goal

Build the Bearblog of Karakeep/Linkwarden: a minimalist, self-hosted PWA where users can quickly dump URLs, files, photos, Markdown notes, and clipboard content into an encrypted searchable archive.

## Non-Goals For V1

- Social sharing.
- Multi-tenant organizations.
- Browser automation/crawling beyond URL capture metadata.
- Rich WYSIWYG editing.

## Core Capabilities

### Authentication

- Users can register with email and password.
- Users can log in and receive a secure HTTP-only session cookie.
- User data is isolated by authenticated user ID.
- Passwords are stored with salted password hashes, never plaintext.
- Public deployments must be able to close registration. Open registration is a local/self-hosting convenience, not a safe production default.
- Production session cookies must be `HttpOnly`, `Secure`, and use a restrictive same-site policy.

### Privacy And Security Hardening

Priority order:

1. Lock down public registration and production cookies before storing private data on the VPS.
2. Keep uploaded file/photo bytes out of rendered text surfaces; render images as previews and store binary payloads through a blob storage adapter.
3. Preserve user control through import/export before adding higher-level capture automation.
4. Add metadata fetching only as an explicit capture enhancement, with conservative network timeouts and no background crawling.

### Plans And Sustainability

Potpuri should remain useful without payment. Hosted-plan enforcement should be modelled in public code as neutral capabilities and limits, while payment-provider integration can live outside the public repository.

Free hosted tier:

- Generous bookmarks and text notes.
- Storage budget around 100-250MB.
- Unlimited devices.
- Bookmarklet and browser extension.
- API token.
- Export.
- Basic search.
- Public/private entries if sharing is added.
- 2FA when implemented; account security must not be paywalled.

Supporter hosted tier:

- $1/month or $10/year target.
- 1GB storage.
- Unlimited entries within abuse limits.
- Larger attachments, around 25-50MB/file.
- Priority export/backups.
- Optional subtle supporter badge.
- Early features where appropriate.

### Capture

- Users can create an item with a title, type, body, optional source URL, and tags.
- Supported item types:
  - `note`
  - `url`
  - `file`
  - `photo`
- Each item stores `created_at`, used for default insertion-date ordering.
- Mobile PWA supports “add to Potpuri from clipboard” through the Clipboard API when available.
- iOS supports share-sheet capture through a user-created Shortcut backed by `POST /api/shortcut`, because iOS does not expose PWA Web Share Target entries in the native share sheet.
- Browser extension supports:
  - Context-menu capture of the current page/link/selection.
  - Add to Potpuri from clipboard.
- A bookmarklet should support quick URL capture without installing an extension.
- URL capture should optionally fetch metadata such as page title, description, and preview image to reduce link rot, without full-page crawling in V1.

### Files And Photos

- Files/photos should be stored as blobs rather than inlining base64 in editable note text.
- Blob metadata belongs with the item and remains user-scoped.
- Renderable images should display inline with rounded corners.
- Existing base64-backed uploads should remain readable during migration.

### Import And Export

- Users can export their archive.
- Export formats:
  - JSON for full-fidelity backup/restore.
  - Markdown for human-readable notes/bookmarks.
  - ZIP bundle for JSON/Markdown plus file/photo blobs.
- Import should accept Potpuri JSON/ZIP exports.

### Encryption

- Sensitive item payload fields are encrypted before database storage.
- Search uses HMAC blind indexes over normalized terms so plaintext body text is not stored for search.
- Operational metadata required for listing/filtering, such as user ID, timestamps, item type, and tags, is stored in queryable form.
- Encryption key is supplied by deployment secret, not hard-coded.

### Tags

- Items can have zero or more tags.
- Tags are normalized to lowercase slugs.
- The catalogue is extensible: tags are created by use and can later gain metadata without changing item storage.
- UI should support tag picking, tag filtering, and visible active filters.

### Search

- Search performs rich textual matching over item title/body/source URL tokens via blind-index tokens.
- Search is scoped to the authenticated user.
- Results are ordered by insertion date descending.

### Listing

- The default item list shows newest inserted entries first.
- The list shows decrypted title/body snippets only for the authenticated user.

## Architecture

### Clean Architecture

- Domain models contain core vocabulary and invariants.
- Use cases expose behavior-oriented methods.
- Storage, HTTP, and crypto are adapters behind interfaces.
- Postgres is the production repository adapter.

### Factory Pattern

- `internal/app.Factory` builds the application graph from environment/config.
- Tests can construct the same use cases with in-memory repositories and deterministic secrets.

## API Surface

### HTML

- `GET /` list/search/create form.
- `GET /register`
- `POST /register`
- `POST /login`
- `POST /logout`
- `POST /items`
- `GET /items/edit`
- `POST /items/edit`
- `POST /items/delete`
- `GET /manifest.webmanifest`
- `GET /sw.js`

### JSON API

- `POST /api/items`
- `GET /api/items`
- `GET /api/items?q=...`
- `POST /api/clipboard`
- `POST /api/shortcut`

The browser extension and PWA clipboard action use the JSON API.
The iOS Shortcut uses a form-encoded API so users can configure it with Shortcuts' built-in “Get Contents of URL” action.

## Deployment

- Target: single VPS.
- Runtime: Go HTTP binary.
- Database: Postgres.
- TLS/reverse proxy: Caddy or nginx.
- Required environment:
  - `POTPURI_DATABASE_URL`
  - `POTPURI_ENCRYPTION_KEY`
  - `POTPURI_SESSION_SECRET`
  - `POTPURI_ADDR` optional, defaults to `:8080`
  - `POTPURI_ALLOW_REGISTRATION` optional, defaults to `false` in production factory wiring.
  - `POTPURI_SECURE_COOKIES` optional, defaults to `true` in production factory wiring.

## Test Strategy

- Use-case tests verify user-facing behavior through public interfaces.
- Crypto tests verify decryptability and no plaintext leakage.
- HTTP tests verify authentication boundaries and end-to-end capture/search behavior.
- Postgres adapter tests can be added behind an integration build tag once Docker/Postgres is available.
