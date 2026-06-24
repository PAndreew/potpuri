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

### Capture

- Users can create an item with a title, type, body, optional source URL, and tags.
- Supported item types:
  - `note`
  - `url`
  - `file`
  - `photo`
- Each item stores `created_at`, used for default insertion-date ordering.
- Mobile PWA supports “add to Potpuri from clipboard” through the Clipboard API when available.
- Browser extension supports:
  - Context-menu capture of the current page/link/selection.
  - Add to Potpuri from clipboard.

### Encryption

- Sensitive item payload fields are encrypted before database storage.
- Search uses HMAC blind indexes over normalized terms so plaintext body text is not stored for search.
- Operational metadata required for listing/filtering, such as user ID, timestamps, item type, and tags, is stored in queryable form.
- Encryption key is supplied by deployment secret, not hard-coded.

### Tags

- Items can have zero or more tags.
- Tags are normalized to lowercase slugs.
- The catalogue is extensible: tags are created by use and can later gain metadata without changing item storage.

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
- `POST /register`
- `POST /login`
- `POST /logout`
- `POST /items`
- `GET /manifest.webmanifest`
- `GET /sw.js`

### JSON API

- `POST /api/items`
- `GET /api/items`
- `GET /api/items?q=...`
- `POST /api/clipboard`

The browser extension and PWA clipboard action use the JSON API.

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

## Test Strategy

- Use-case tests verify user-facing behavior through public interfaces.
- Crypto tests verify decryptability and no plaintext leakage.
- HTTP tests verify authentication boundaries and end-to-end capture/search behavior.
- Postgres adapter tests can be added behind an integration build tag once Docker/Postgres is available.

