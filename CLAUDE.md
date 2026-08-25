# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`server` is a **Frappe v16 app** ("Managing the server and frappe benches"). It is not standalone — it
only runs as part of a bench. This checkout lives at `apps/server` inside the bench at
`/home/patoo/fb-16-server`, whose default site is `local.16.server` (webserver port `8008`, socketio
port `9008`).

Two halves:

- `server/` — the Python Frappe app (hooks, www pages, patches, module `Server`).
- `serving/` — a Vue 3 + TypeScript + Vite SPA, originally scaffolded by
  [doppio](https://github.com/NagariaHussain/doppio) (`bench add-spa`) but now self-contained, served by
  the Frappe backend at `/serving`.

It does two things: **watch SSH** (who logged in, from where, and every `sudo` they ran) and **manage
benches** (install apps from private GitHub repos, run bench commands, set up SSL, restore sites).

## Commands

All `bench` commands run from the **bench root** (`/home/patoo/fb-16-server`), not from this directory.

```bash
# Backend
bench --site local.16.server migrate              # apply patches + schema
bench --site local.16.server console               # python REPL with frappe loaded
bench --site local.16.server clear-cache
bench start                                        # web + socketio + workers + watch (Procfile)

# Tests — 377 of them, most needing neither a site nor a database.
# Use the BENCH VENV python: one module imports frappe, and the venv is the
# interpreter the app actually runs under (3.14, not this box's system 3.12).
../../env/bin/python -m unittest discover -s server/tests -t .
../../env/bin/python -m unittest server.tests.test_restore     # one module

# 34 of them need a site connection and skip without one, so the run above
# reports ~37 skips and ~325 passes. Run them through a site to exercise
# those too — 377 tests, 3 skips (the certbot-dependent ones):
bench --site local.16.server set-config allow_tests true   # once per site
bench --site local.16.server run-tests --app server
bench --site local.16.server run-tests --module server.tests.test_x   # single module
bench --site local.16.server run-tests --doctype "Some DocType"

# Frontend (from apps/server)
yarn dev      # -> serving/: vite dev server on :8080, proxies /api|/app|/assets|/files|/private to :8008
yarn build    # -> serving/: vite build + copy-html-entry (see below)

# Lint / format — ruff and eslint/prettier run via pre-commit
pre-commit install
pre-commit run --all-files
ruff check server/ && ruff format server/
```

## The `/serving` SPA wiring

This is the part that requires reading several files to understand. Requests flow:

1. `website_route_rules` in [server/hooks.py](server/hooks.py) maps `/serving/<path:app_path>` → the www
   page `serving`, so client-side routes deep-link correctly.
2. [server/www/serving.py](server/www/serving.py) supplies `get_context()`, which injects a CSRF token and
   a `boot` dict (frappe version, site name, read-only flag, timezone) into the page. `get_context_for_dev`
   is a whitelisted guest endpoint that returns the same boot payload, but **only** when
   `developer_mode` is on — the Vite dev server has no Jinja, so that is how the dev build gets boot data.
3. `serving/index.html` is the Vite entry. Its inline script sets `window.csrf_token` from a Jinja
   expression, which is inert under `yarn dev` and only interpolates once Frappe renders the built HTML.
4. `yarn build` writes to `server/public/serving/` with `--base=/assets/server/serving/`, then
   `copy-html-entry` copies the built `index.html` to **`server/www/serving.html`**. That copy is what makes
   `/serving` render at all.

**Gotcha:** `server/www/serving.html` is a build artifact, not source. A fresh checkout has only
`serving.py`, so `/serving` will not work until `yarn build` has been run at least once. `server/public/`
is exposed to the browser through the `sites/assets/server` symlink.

## No cross-app dependencies

The SPA used to import through `../../../doppio/libs/...`, which escaped this repo and required the
doppio app to be present in the bench just to build. That is gone: `serving/src/lib/` now carries its own
`auth`, `call`, `resource` and `socket`. The app builds and installs on a bench that has only frappe.

Two things that were doppio bugs and are now ours to keep right:

- the socket client reads the socketio port from the injected `boot`, rather than hardcoding `9000`
  (this bench runs socketio on `9008`);
- `createWebHistory("/serving")` must stay in sync with the route rule in `hooks.py` and the `--base`
  flag in `serving/package.json`.

## Bench operations

Everything that runs a subprocess goes through one path: an **`App Install Request`** row, queued to the
`long` worker, holding a bench-scoped lock, streaming its output to `output` and to the browser. The
`operation` field picks the branch — `Clone`, `Pull`, `Command`, `SSL`, `Restore`. Adding a sixth means
a branch in `installer.py`, not a new doctype.

The rules that path exists to enforce, each learned from a real failure:

- **`stdin` is always `DEVNULL`.** Anything that prompts must fail immediately instead of hanging. This
  is why `bench setup lets-encrypt` gets `-n`, and why `bench renew-lets-encrypt` is *never* used —
  it calls `click.confirm(abort=True)` with no non-interactive escape, so it would abort every time.
  Renewal drives `certbot renew` directly, which is what bench's own cron entry does.
- **Exit code 0 is not proof of success.** `bench setup lets-encrypt` prints "You cannot setup SSL
  without DNS Multitenancy" and exits 0; `bench get-app` exits 1 from a trailing `supervisorctl` call
  after the app is already installed. Hence `ssl.quiet_failure()` and `installer._clone_landed()`.
- **Secrets never reach `command` or `output`.** `bench restore` only accepts the database root password
  on the command line, so `restore.redact()` produces the copy that is stored and displayed. Credentials
  live in `Password` fields and are cleared in `finish()`, which every terminal path runs through.
- **Pre-flight before side effects.** `_preflight_restore` refuses a missing password or an unkeyed
  encrypted backup *before* `bench restore` drops the database — finding out afterwards means an empty
  site and no way back.

`bench/ssl.py` and `bench/restore.py` are frappe-free, like `ssh/parser.py`, so they unit-test with no
site and no database.

## Conventions

- **Python is tab-indented** (ruff `indent-style = "tab"`), double quotes, line length 110, target
  py3.14. Frappe's ruff preset intentionally ignores `E501`, `F401`, `F403/F405`, `W191`, and most `UP`
  string rules — do not "fix" those.
- Vue/JS/CSS are also tab-indented per `.editorconfig`; `.json` uses 1-space indent and no final newline
  (DocType schema convention).
- `.eslintrc` declares Frappe desk globals (`frappe`, `__`, `cur_frm`, …) — desk-side JS may reference
  them without imports.
- Default branch here is `version-16`; CI runs on pushes to it. The CI job has a `Find tests` step that
  greps for `def test` and **fails when the app has no tests** — adding the first test file is what makes
  CI green.
- New DocTypes go under `server/server/doctype/` (the `Server` module, declared in `server/modules.txt`);
  data migrations go in `server/patches.txt` under `[pre_model_sync]` or `[post_model_sync]`.
