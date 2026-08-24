# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`server` is a **Frappe v16 app** ("Managing the server and frappe benches"). It is not standalone — it
only runs as part of a bench. This checkout lives at `apps/server` inside the bench at
`/home/patoo/fb-16-server`, whose default site is `local.16.server` (webserver port `8008`, socketio
port `9008`).

Two halves:

- `server/` — the Python Frappe app (hooks, www pages, patches, module `Server`).
- `serving/` — a Vue 3 + TypeScript + Vite SPA scaffolded by [doppio](https://github.com/NagariaHussain/doppio)
  (`bench add-spa`), served by the Frappe backend at `/serving`.

The app currently has no DocTypes, no scheduler events, and no doc events — `server/hooks.py` is the
stock boilerplate with a single active line: `website_route_rules`.

## Commands

All `bench` commands run from the **bench root** (`/home/patoo/fb-16-server`), not from this directory.

```bash
# Backend
bench --site local.16.server migrate              # apply patches + schema
bench --site local.16.server console               # python REPL with frappe loaded
bench --site local.16.server clear-cache
bench start                                        # web + socketio + workers + watch (Procfile)

# Tests (there are currently none in this app)
bench --site local.16.server set-config allow_tests true
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

## Cross-app dependency on doppio

[serving/src/main.ts](serving/src/main.ts) imports through `../../../doppio/libs/...`, which escapes this
repo and resolves to `apps/doppio/libs/` in the sibling app. **The frontend will not build unless the
doppio app is present in the bench.** doppio need not be installed on the site (it isn't here — the site
has only `frappe` and `server`); it is a build-time source dependency plus a provider of `bench add-spa`
and friends.

What those shared libs give the SPA, all wired up in `main.ts`:

- `Auth` — provided as `$auth`; derives `isLoggedIn` from the `user_id` cookie, calls Frappe's
  `login`/`logout` methods. `router.beforeEach` uses `meta.isLoginPage` to gate every other route.
- `call` — provided as `$call`; `POST /api/method/<method>` with the CSRF header, unwraps `data.message`,
  and redirects to `/login` on 401/403.
- `resourceManager` — a global mixin adding a `resources` component option, exposed as `$resources`
  (see [serving/src/views/Home.vue](serving/src/views/Home.vue) for the pattern).
- `socket` — provided as `$socket`. Note it hardcodes port `9000`, while this bench runs socketio on
  `9008`; realtime needs that reconciled. Do not edit doppio to fix it — it is a different repo.

The router uses `createWebHistory("/serving")`, so its base must stay in sync with the route rule in
`hooks.py` and the `--base` flag in `serving/package.json`.

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
