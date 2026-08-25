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

### Restoring

Three things happen before `bench restore` is allowed to run, each guarding a failure that is
invisible until it is expensive:

- **`bench/inspect.py` reads the dump's `tabInstalled Application`** and refuses while the bench is
  missing an app the backup references. That restore *appears to succeed* — the site comes up and
  every DocType belonging to the missing app is gone — and surfaces days later as import errors
  nobody connects back to it. Column positions come from the dump's own `CREATE TABLE`; frappe has
  added columns to that table before, and a fixed index would report the version as the branch.
- **`restore.estimate_space()`** refuses when the disk cannot hold the dump expanded (~16×, press's
  own multiplier).
- **The site slug in the filename** is compared to the target site, because right-backup-wrong-site
  looks completely normal until the data is already replaced.

A backup can arrive three ways and they all converge on one `BackupSet`: written by frappe into the
site's own directory, copied into `<bench>/backups/` by hand, or uploaded through
`api.upload_backup` (streamed to disk — a production dump is gigabytes). Retention (`bench/backups.py`)
ranks **only** over the site's own directory, because that is the only place it deletes from; ranking
over the merged listing once let dropped-in files fill the protected window and deleted every backup
a site had.

`bench/ssl.py`, `bench/restore.py`, `bench/inspect.py`, `bench/backups.py`, `bench/steps.py`, `bench/logs.py`,
`bench/siteconfig.py` and `system.py` are frappe-free, like `ssh/parser.py`, so they unit-test with no
site and no database. That is most of the app's logic; keep it that way.

### Steps

Every job announces its plan before it starts and reports which part it is on (`bench/steps.py`,
stored as JSON on the request's `steps` field, rendered by `JobSteps.vue`). Borrowed from press's
`AgentJob` + `FoldStep.vue`. It is not decoration: "it failed" plus 900 lines of git output does not
say *which* part failed, and a restore showing that it is about to take a backup first is only useful
while there is still time to cancel.

### Things that arrive from a browser

Three separate features take a filesystem path from the client — restore (`restore.is_inside`), the
log reader (`logs.is_inside`) and backup pruning. All three resolve the path before comparing, because
`../..` and a planted symlink both defeat a prefix check, and one directory above the logs sits
`common_site_config.json` with the database credentials in it. Any new path-taking endpoint needs the
same treatment plus a test that tries to escape.

### Secrets

`Password` fields keep the encrypted value in `__Auth` and leave a `*****` placeholder in the doctype
column. Clearing the column removes the mask and leaves the secret — `remove_encrypted_password` is
what actually deletes it. `restore.redact()` produces the copy of an argv that is safe to store and
display, because `bench restore` only accepts the database root password on the command line.
`siteconfig.is_secret()` redacts by suffix as well as by name, so a key nobody anticipated is hidden
by default rather than leaked by omission.

## Alerting

`server/alerts.py`, on the scheduler. Three intrusion patterns (root login, first login from a new
country, failed-login burst) and disk pressure. Flood control is frappe's `dedupe_on` plus the date
folded into the subject, which turns "skip duplicates" into "tell me once a day".

Two things that silently broke delivery and will again if changed:

- recipients must be **email addresses**, not User names. Frappe matches `User.email`, and for every
  ordinary user those are the same string — but `Administrator` is named `Administrator` and has a
  separate email, so a fresh single-admin server delivered nothing.
- `notification_self_notify_types = ["Alert"]` in `hooks.py`. Frappe drops a notification whose
  recipient is also its sender; on that same single-admin server that dropped the rest.

Alerts surface in the SPA sidebar (`AlertsPanel.vue`), not only in the desk at `/app` — an alert
nobody looks at is the same as no alert.

## Server health

`server/system.py` reads `/proc` and `shutil.disk_usage`; no psutil, no dependency. Load is reported
per CPU because 8 is idle on 16 cores and on fire on 2, and memory uses `MemAvailable` rather than
`MemFree` (which excludes the page cache and makes a healthy machine look full). Disk is the one that
matters: it fills gradually, takes every site down at once, and the cause is nearly always backups —
so `backup_usage()` names which site is responsible, and `bench/backups.py` prunes them under rules
that cannot be argued below (`MIN_KEEP`, `MIN_AGE_HOURS`).

## Invariants

Rules that cost real time to learn. `server/tests/test_app_wiring.py` enforces the first two.

1. **Every `@frappe.whitelist` calls `_assert_server_admin()`**, and every mutating one declares
   `methods=["POST"]`. This app runs commands as the bench user; a missing guard is a hole, not a
   bug. Anything that spawns a process also calls `assert_installs_allowed()` — that switch is
   documented as the kill switch for all subprocess activity, so a path that ignores it makes the
   documentation a lie.
2. **`shell=False` is not input validation.** git takes options that name a command to run, so a
   remote beginning with `-` is an argument of git's choosing:
   `git ls-remote --heads "--upload-pack=touch /tmp/x; git-upload-pack" /repo` runs `touch` and
   exits 0. Validate the value, and put `--` before positionals.
3. **`emit()` and `flush()` in the job body must never raise.** Every failure path calls them on the
   way out, so an exception there surfaces from inside the handler reporting the first one — the
   worker dies and the row says Running forever. `test_job_end_to_end.py` exists because 404 unit
   tests passed while exactly this was broken.
4. **A log line is not a fact about the world.** sshd escapes control characters in a username but
   not spaces, so a client that connects as `b from 10.0.0.1` puts a well-formed address of its
   choosing into the message. Trust the clause sshd writes itself (`from <ip> port <n>`), and
   validate anything that becomes a docname — a bad one aborts the batch, and a batch that aborts
   never advances the checkpoint, so ingestion stops permanently.
5. **Exit code 0 is not success, and neither is a `Password` field being cleared.** `db_set(field,
   None)` removes the `*****` mask and leaves the encrypted value in `__Auth`;
   `remove_encrypted_password` is what deletes it.

### A DocField must never be called `process`

`Meta.__init__` builds itself from the DocType document, so a field named `process` shadows
`frappe.model.meta.Meta.process()` and the migration dies with `TypeError: 'NoneType' object is not
callable` — pointing at frappe's own code, with nothing naming the field responsible. Cost an hour.
Same hazard for any other `Meta` method name.

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
