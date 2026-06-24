# Potpuri

Potpuri is a small, self-hosted personal archive for files, photos, URLs, and Markdown notes.

The first implementation slice includes:

- Built-in account registration and login.
- Encrypted item body storage with AES-GCM.
- Blind-indexed text tokens for search without storing plaintext search text.
- Insertion-date item listing by default.
- Minimal server-rendered HTML with a PWA manifest and service worker.
- A browser extension skeleton with context-menu and clipboard capture.

## Run Locally

```sh
export POTPURI_DATABASE_URL='postgres://potpuri:potpuri@localhost:5432/potpuri?sslmode=disable'
export POTPURI_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export POTPURI_SESSION_SECRET="$(openssl rand -base64 32)"
go run ./cmd/potpuri
```

Then open `http://localhost:8080`.

## Test

```sh
go test ./...
```

## Architecture

The code is intentionally split into clean layers:

- `internal/domain`: entities and value objects.
- `internal/ports`: interfaces between use cases and adapters.
- `internal/usecase`: application behavior.
- `internal/security`: encryption, search tokenization, password hashing.
- `internal/storage/postgres`: Postgres adapter.
- `internal/web`: HTTP/PWA adapter.
- `internal/app`: factory wiring.

