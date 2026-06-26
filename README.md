<p align="center">
  <img src="internal/web/static/rose.svg" alt="Potpuri" width="96" height="96">
</p>

# Potpuri

A minimalist, privacy-focused bookmarking application inspired by Bearblog.



https://github.com/user-attachments/assets/f1d52ab6-43eb-4f9c-8c1e-589bdc2290ef



## Disclaimers

**On AI-assisted development:** Potpuri is being developed with Codex and Claude Code. I try to keep the scope of the project narrow and avoid frontend frameworks. The backend is written in Go, which has a low keyword set and relies mostly on its standard library — this hopefully makes it harder for LLMs to jumble things up. I think LLMs make it more pleasant to follow the TDD paradigm, so I always start with failing tests and then implement the actual features. As the project matures, LLM-reliance will decrease over time.

**On monetisation:** The majority of Potpuri's features are free to use. I don't collect or sell any user data and don't serve ads. Since the hosting, development, and maintenance of such a project costs money, I added a Patron tier — the main benefit is extra storage and longer retention.

## Why?

I — as basically all human beings at this point — use multiple devices to manage my life and wanted an easy and secure way to preserve, share, and access data on these devices. In my experience, other popular bookmark apps like Linkwarden and Karakeep chugged the LLM pill — even their landing pages reek of LLM aesthetics (no offense). I'm not an LLM luddite (see the disclaimer above), but I'm not sure I want to send my personal digital trinkets to these people's servers just to extract 3 keywords from them. Also, the UI seems to be a bit intimidating. So, thank you, but no, thank you. I'm a big fan of Herman's Bearblog, and then it just hit me: I'm gonna roll my minimalist digital treasure trove.

## What?

Here is a list of what Potpuri offers for free:

- Encrypted storage — only you can read your stuff
- PWA, installable on Android and iOS*
- Unlimited devices
- Bookmarklet to easily save content from your browser
- iOS Shortcut recipe for saving from the share sheet
- Save text in Markdown format
- Save photos and other files, like PDF docs (max 25 MB per entry)
- Edit and delete items
- Add tags
- Import and export data
- 250 MB storage
- Share through secret link
- One API key
- No frontend fluff

And here are a few additions you get if you become a Patron:

- Email-to-save
- 5 GB storage
- 100 MB per entry upload limit
- Multiple API keys
- Optional custom domain
- Priority support
- My endless gratitude

## Self-hosting

Potpuri can be self-hosted — see [self-hosting.md](self-hosting.md) for details.

## Run locally

```sh
export POTPURI_DATABASE_URL='postgres://potpuri:potpuri@localhost:5432/potpuri?sslmode=disable'
export POTPURI_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export POTPURI_SESSION_SECRET="$(openssl rand -base64 32)"
go run ./cmd/potpuri
```

Then open `http://localhost:8080`.

## Run tests

```sh
go test ./...
```

## Architecture

The code is split into clean layers:

- `internal/domain` — entities and value objects
- `internal/ports` — interfaces between use cases and adapters
- `internal/usecase` — application behaviour
- `internal/security` — encryption, search tokenisation, password hashing
- `internal/storage/postgres` — Postgres adapter
- `internal/storage/r2` — Cloudflare R2 blob storage adapter
- `internal/web` — HTTP and PWA adapter
- `internal/app` — factory wiring

## Contributing

I am following Herman's steps in the sense that I'd like to keep the set of direct contributors narrow, but if you have a feature request or have encountered a bug, please open an issue or write to me directly.

Have a great day and happy hunting.

## iOS Shortcut

*iOS does not expose installed PWAs as Web Share Target apps in the share sheet.
To save from iOS, create a Shortcut named `Save to Potpuri`.

In Potpuri, create one API token from `/tokens`. The same token can be used for
both the bookmarklet and the iOS Shortcut.

Configure the Shortcut like this:

1. Open the Shortcut details, enable `Show in Share Sheet`, and set `Receive` to URLs, Safari webpages, and text. If the shortcut does not show up in some apps, temporarily add `Any` while testing.
2. Add a `URL` action containing your Potpuri shortcut endpoint:

```text
https://your-domain.example/api/shortcut
```

3. Add `Get Details of Shortcut Input` for `Name`; use that value as the `title` form field.
4. Add `Get Details of Shortcut Input` for `URL`; use that value as the `url` form field.
5. Add `Text` containing `Shortcut Input`; use that value as the `text` form field.
6. Add `Get Contents of URL`, choose method `POST`, choose request body `Form`, and add these fields:

```text
token = your Potpuri API token
title = Name from Shortcut Input
url = URL from Shortcut Input
text = Shortcut Input
```

Use `Get Contents of URL`, not `Share` or `Share with Apps`. The Share actions
send content onward to another app; Potpuri needs an HTTP POST to the shortcut
endpoint. `Run JavaScript on Webpage` is optional and Safari-only: use it only
if you want to extract selected text or page metadata from Safari, then pass
that result into the same `Get Contents of URL` POST.
