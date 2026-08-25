# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Running `bench get-app` from a background job, safely.

THE WHOLE PROBLEM IS THAT bench IS AN INTERACTIVE CLI. It prompts before
overwriting an app directory, git prompts for credentials, and ssh prompts for a
key passphrase. Any one of those inside an RQ worker is a job that never
finishes and a worker slot that never comes back. Four independent layers stop
that, and they are independent on purpose — each one alone would be enough on a
good day:

1. `stdin=DEVNULL`. click's `confirm()` catches EOFError and raises Abort, so
   the prompt turns into an immediate non-zero exit instead of a wait.
2. `GIT_TERMINAL_PROMPT=0` and `BatchMode=yes` in GIT_SSH_COMMAND, so git and
   ssh fail rather than ask. There is no ssh-agent under a worker, so a
   passphrase-protected key is unusable and must fail fast rather than hang.
3. A pre-flight that refuses to run at all when the app directory exists and
   Overwrite is not ticked — the prompt is designed out, not survived.
4. A watchdog. `start_new_session=True` puts the child in its own process
   group so the whole tree — bench, git, pip — can be killed together;
   killing only the bench wrapper would orphan a running git clone.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time

import frappe
from frappe.utils.synchronization import LockTimeoutError, filelock

from server.bench import commands, doctor, restore, scanner, ssl, steps as step_plan
from server.server.doctype.server_settings.server_settings import get_settings

#: How often, at most, to push log lines to a watching browser.
STREAM_INTERVAL = 0.25

#: How often to flush the accumulated log to the database, so a crash still
#: leaves a usable trail rather than an empty Output field.
PERSIST_EVERY_LINES = 40

#: How often a running job checks whether someone asked it to stop.
CANCEL_POLL_SECONDS = 2.0

#: Cancellation goes through Redis, not the database.
#:
#: The worker sits inside one long transaction, and MariaDB's REPEATABLE READ
#: means a flag committed by the web process afterwards is invisible to it — the
#: worker would keep reading its own stale snapshot and never see the request.
#: The cache has no such snapshot.
CANCEL_KEY = "server:cancel-request:{name}"

#: A job whose worker died leaves the row saying Running forever, and for a
#: restore that also leaves the database root password sitting in the record.
#: Anything past its own timeout by this much is presumed dead.
STALE_GRACE_SECONDS = 300

#: git redraws progress with \r; both count as end-of-line for the log.
_LINE_BREAK = re.compile(r"[\r\n]")

LOG_EVENT = "server:app_install_log"
DONE_EVENT = "server:app_install_done"
STEP_EVENT = "server:app_install_steps"

#: bench ends a get-app by calling `sudo supervisorctl status` to decide whether
#: to restart processes. On a host with no passwordless sudo that raises, and
#: bench exits 1 — AFTER the app has been cloned and pip-installed. It does this
#: even when restart_supervisor_on_update and restart_systemd_on_update are both
#: false, which is how two perfectly good erpnext clones were reported as
#: failures here.
_SUPERVISOR_POSTSTEP = re.compile(r"supervisorctl|restart_supervisor_processes", re.IGNORECASE)

#: exit_code when the command was never executed at all — a pre-flight refused
#: it. A frappe Int column is NOT NULL, so None is not storable, and 0 already
#: means "ran and succeeded". Writing None here throws a MySQL error from inside
#: the failure handler, which then replaces the actionable pre-flight message
#: with a column constraint error — the operator is told about a database
#: problem instead of the missing branch that actually stopped them.
NEVER_RAN = -1


class InstallAborted(Exception):
	"""A pre-flight refused to run the command. Carries an actionable message."""


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def _preflight(request, bench_doc, settings, on_step=None) -> list[str]:
	"""Everything checkable cheaply, before spending minutes on a subprocess."""
	settings.assert_installs_allowed()
	bench_doc.assert_usable()

	if not request.app_name:
		raise InstallAborted("No app name could be derived from the source.")

	bench_exe = (settings.bench_executable or "").strip()
	if not bench_exe.startswith("/"):
		raise InstallAborted("Bench Executable must be an absolute path — workers do not inherit your PATH.")
	if not os.path.isfile(bench_exe) or not os.access(bench_exe, os.X_OK):
		raise InstallAborted(f"{bench_exe} is not an executable file.")

	if request.is_command():
		return _preflight_command(request, bench_doc)
	if request.is_ssl():
		return _preflight_ssl(request, bench_doc)
	if request.is_restore():
		return _preflight_restore(request, bench_doc)
	if request.is_pull():
		return _preflight_pull(request)
	return _preflight_clone(request, bench_doc, on_step)


def _preflight_command(request, bench_doc) -> list[str]:
	"""Confirm the command still exists, is runnable, and its site is real."""
	command = commands.get(request.bench_command or "")
	if not command:
		raise InstallAborted(f"{request.bench_command!r} is not a known bench command.")
	if not command.runnable:
		raise InstallAborted(command.unsupported_reason or f"{command.label} cannot be run from here.")

	if command.scope == commands.SCOPE_SITE:
		site = (request.install_on_site or "").strip()
		if site not in bench_doc.site_names():
			raise InstallAborted(
				f"{site!r} is not a site on {bench_doc.name}. "
				f"Known sites: {', '.join(bench_doc.site_names()) or 'none'}."
			)

	notes = [f"{command.label} · {command.risk}"]
	if command.risk == commands.RISK_DESTRUCTIVE:
		# Recorded in the log itself, so the record of what happened carries the
		# warning that was shown before it happened.
		notes.append("This command is destructive and no backup was taken automatically.")
	return notes


def _preflight_ssl(request, bench_doc) -> list[str]:
	"""Refuse an SSL run that cannot possibly work.

	Every one of these takes milliseconds and each maps to a failure that would
	otherwise surface minutes later — one of them (no DNS multitenancy) as a
	successful run that did nothing at all.
	"""
	mode = request.ssl_mode_key()
	if not mode:
		raise InstallAborted("No SSL operation was chosen.")

	if not ssl.certbot_path():
		raise InstallAborted(
			"certbot is not installed on this server. Install it with "
			"`sudo apt install certbot python3-certbot-nginx`, then try again."
		)

	if not ssl.has_passwordless_sudo():
		raise InstallAborted(
			"certbot and nginx both need root, and this job has no terminal to type a password "
			"into. Give this user a NOPASSWD sudoers rule before running SSL from here."
		)

	if mode == ssl.MODE_ISSUE:
		site = (request.install_on_site or "").strip()
		if site not in bench_doc.site_names():
			raise InstallAborted(f"{site!r} is not a site on {bench_doc.name}.")
		if not ssl.is_dns_multitenant(bench_doc.bench_path):
			raise InstallAborted(
				"This bench is not DNS-multitenant, and bench refuses to set up SSL without it — "
				"while still exiting 0, so it would look like it worked. Run "
				"`bench config dns_multitenant on` first."
			)
		domain, extras = ssl.site_domains(bench_doc.bench_path, site)
		target = (request.ssl_domain or "").strip() or domain
		if not ssl.VALID_DOMAIN.match(target):
			raise InstallAborted(
				f"{target!r} is not a public domain name, so Let's Encrypt cannot certify it. "
				"Point a real domain at this server and set it as the site's host_name."
			)
		if request.ssl_domain and request.ssl_domain.strip() not in extras:
			raise InstallAborted(
				f"{request.ssl_domain} is not one of {site}'s configured domains "
				f"({', '.join(extras) or 'none'}). bench only certifies a domain the site already "
				"knows about — add it with `bench setup add-domain` first."
			)

		# Let's Encrypt rate-limits failed authorisations and the block outlasts
		# the mistake, so a domain that cannot possibly validate is refused here
		# rather than spent. A domain that resolves somewhere else is only a
		# warning: behind a proxy or Cloudflare that is entirely normal.
		dns = ssl.dns_check(target)
		if dns["level"] == "danger":
			raise InstallAborted(
				dns["detail"] + " Nothing was changed and no certificate request was made."
			)

		notes = [f"Issue certificate for {target} · nginx will restart"]
		if not dns["points_here"]:
			notes.append(dns["detail"])
		return notes

	return [
		"Renew certificates" + (" (dry run — nothing installed)" if request.ssl_dry_run else ""),
		"nginx stops for the check and starts again afterwards, even if renewal fails.",
	]


def _preflight_restore(request, bench_doc) -> list[str]:
	"""Refuse a restore that cannot work, before the database is dropped.

	The ordering matters: everything that would leave the site broken is
	checked before anything that merely fails.
	"""
	site = (request.install_on_site or "").strip()
	if site not in bench_doc.site_names():
		raise InstallAborted(f"{site!r} is not a site on {bench_doc.name}.")

	try:
		backup = request.resolve_backup(bench_doc.bench_path)
	except restore.RestoreRefused as exc:
		raise InstallAborted(str(exc)) from exc

	if not os.path.isfile(backup.database):
		raise InstallAborted(f"{backup.database} is gone. Nothing was changed.")

	password = request.get_password("restore_db_password", raise_exception=False)
	if not password:
		raise InstallAborted(
			"The database root password is missing. bench restore cannot drop and recreate the "
			"database without it, and there is no terminal here for it to ask on."
		)

	if backup.encrypted and not request.get_password("restore_encryption_key", raise_exception=False):
		raise InstallAborted(
			"That backup is encrypted and its encryption key was not supplied. Restoring would "
			"drop the database and then fail to load anything into it."
		)

	notes = [f"Restore {site} from {backup.taken_at} ({backup.source} backup)"]
	mismatch = restore.describe_mismatch(backup, site)
	if mismatch:
		notes.append(mismatch)
	if not request.restore_backup_first:
		notes.append("No backup was taken first — this was explicitly turned off.")
	return notes


def _preflight_clone(request, bench_doc, on_step=None) -> list[str]:
	app_path = request.app_path
	if os.path.isdir(app_path) and not request.overwrite_existing:
		raise InstallAborted(
			f"{app_path} already exists. Tick 'Overwrite If Present' to replace it — "
			"bench archives the old copy to archived/apps/ rather than deleting it. "
			"To update it in place instead, use a Pull."
		)

	if request.install_on_site and request.install_on_site not in bench_doc.site_names():
		raise InstallAborted(
			f"{request.install_on_site!r} is not a site on {bench_doc.name}. "
			f"Known sites: {', '.join(bench_doc.site_names()) or 'none'}."
		)

	# The highest-value check in the file: proves the key is authorised and the
	# branch exists in about a second, rather than three minutes into a clone
	# with a message that blames the repository for not existing. It reaches the
	# network, so it gets its own step — "verifying access" hanging for ten
	# seconds should not look like "checking options" hanging.
	if on_step:
		on_step("access")
	probe = doctor.check_repo(request.resolved_git_url, request.branch or None)
	if not probe["reachable"]:
		raise InstallAborted(f"Cannot reach {request.resolved_git_url}. {probe['error']}")
	if not probe["branch_exists"]:
		raise InstallAborted(probe["error"] or f"Branch {request.branch!r} not found.")
	return [f"Remote reachable; branch {request.branch or '(default)'} present."]


def _preflight_pull(request) -> list[str]:
	"""Checks specific to updating an app that is already on disk."""
	app_path = request.app_path
	if not os.path.isdir(app_path):
		raise InstallAborted(f"{app_path} does not exist. Use a Clone to bring the app in first.")
	if not os.path.isdir(os.path.join(app_path, ".git")):
		raise InstallAborted(f"{app_path} is not a git checkout, so there is nothing to pull.")

	app = scanner.read_app(app_path)
	if not app.remote_name:
		raise InstallAborted(
			f"{request.app_name} has no git remote configured, so there is nowhere to pull from."
		)

	# A pull into a dirty tree is how you get a conflicted checkout that nobody
	# expected and that this job cannot resolve. Refusing is the kind thing.
	if app.is_dirty:
		raise InstallAborted(
			f"{app_path} has uncommitted or untracked changes. Commit, stash or discard them "
			"before pulling — pulling over them would leave the checkout in a conflicted state "
			"that this job cannot resolve for you."
		)

	notes = [f"{request.app_name} is on {app.branch or 'an unknown branch'} via '{app.remote_name}'."]
	if app.is_shallow:
		# bench clones --depth 1. A pull still works, but the history is not
		# there, so say so rather than letting a confusing git error do it.
		notes.append(
			"This is a shallow clone (bench uses --depth 1). A pull works, but git may refuse if "
			"the branch has been force-pushed."
		)
	return notes


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


def build_get_app_argv(request, settings) -> list[str]:
	"""Assemble the `bench get-app` argv.

	`app_name` is passed POSITIONALLY. bench's signature is
	`get-app [name...] <git-url>`, and supplying the name stops bench deriving
	it from the URL — which it gets wrong when the URL carries an SSH host
	alias, producing an app directory named after the alias.

	`--resolve-deps` is deliberately never used. It fetches hooks.py over
	GitHub's raw HTTP API and swallows the failure for a private repository,
	silently resolving to no dependencies at all.
	"""
	argv = [settings.bench_executable, "get-app", request.app_name, request.resolved_git_url]
	if request.branch:
		argv += ["--branch", request.branch]
	if request.skip_assets:
		argv.append("--skip-assets")
	if request.overwrite_existing:
		argv.append("--overwrite")
	return argv


def build_pull_argv(request, app) -> list[str]:
	"""`git pull` inside the app directory.

	`--ff-only` by default, and that is the important part: without it, git
	invents a merge commit whenever the local branch has diverged, and an
	unattended job silently rewriting history in someone's app checkout is not
	a thing this should ever do quietly. Refusing and saying why is better.

	The remote comes from what the checkout actually has — bench clones with
	`--origin upstream`, so assuming `origin` would fail on every app bench
	installed.
	"""
	argv = ["git", "pull"]
	if not request.allow_merge:
		argv.append("--ff-only")
	argv.append(app.remote_name)
	if request.branch:
		argv.append(request.branch)
	elif app.branch and app.branch != "HEAD":
		argv.append(app.branch)
	return argv


def build_install_app_argv(request, settings) -> list[str]:
	"""`bench --site X install-app Y` — a frappe command, not a bench one."""
	argv = [settings.bench_executable, "--site", request.install_on_site, "install-app", request.app_name]
	if request.force_install:
		argv.append("--force")
	return argv


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _stream(
	argv: list[str], cwd: str, env: dict, timeout: int, on_line, should_cancel=None
) -> tuple[int, bool]:
	"""Run a command, streaming combined output. Returns (exit_code, timed_out).

	The flag matters. A watchdog kill surfaces as exit -15, which is
	indistinguishable from any other SIGTERM by exit code alone — and inferring
	the cause produced a real, badly wrong message: a 30-minute erpnext pull was
	killed by the timeout and the operator was told the branch had diverged.

	stderr is folded into stdout so the log reads in the order things actually
	happened. That makes the text unusable as a success signal, which is why the
	exit code is the only thing the caller trusts.

	WHY THE TIMEOUT IS A TIMER AND NOT A CHECK IN THE LOOP. The obvious shape is
	`for line in proc.stdout: ... if past_deadline: kill`, and it does not work.
	Iterating a pipe BLOCKS until the next line arrives, so the deadline is only
	evaluated when the command produces output — and a command that hangs
	silently produces none. That is precisely the case the watchdog exists for:
	a prompt waiting on input, or a clone stalled on a dead connection, both go
	quiet and would wait forever. A timer thread fires regardless of whether
	anything is being read, kills the process group, and the read loop then ends
	on its own because the pipe closes.
	"""
	proc = subprocess.Popen(
		argv,
		cwd=cwd,
		env=env,
		stdin=subprocess.DEVNULL,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		# BINARY, unbuffered, and read with os.read below. Text mode wraps the
		# pipe in a TextIOWrapper whose iterator only yields on a newline, and
		# git writes progress with CARRIAGE RETURNS — so a `git fetch` that runs
		# for twenty minutes produces an empty log until the moment it finishes,
		# which is indistinguishable from a hung job. Verified on a real
		# erpnext pull that showed nothing at all while clearly working.
		bufsize=0,
		start_new_session=True,
	)

	timed_out = threading.Event()
	finished = threading.Event()

	def _on_deadline():
		timed_out.set()
		_kill_group(proc)

	watchdog = threading.Timer(timeout, _on_deadline)
	watchdog.daemon = True
	watchdog.start()

	# Cancellation runs on its own poller for the same reason the timeout does:
	# the read loop blocks on the pipe, so a job that has gone quiet — which is
	# exactly the one you want to cancel — would never notice the request.
	def _watch_for_cancel():
		while not finished.wait(CANCEL_POLL_SECONDS):
			try:
				if should_cancel():
					on_line("--- cancelled; stopping the process group ---")
					_kill_group(proc)
					return
			except Exception:  # noqa: BLE001 - a broken check must not kill the job
				return

	canceller = None
	if should_cancel:
		canceller = threading.Thread(target=_watch_for_cancel, daemon=True)
		canceller.start()

	try:
		pending = ""
		fd = proc.stdout.fileno()
		while True:
			try:
				chunk = os.read(fd, 4096)
			except OSError:
				break
			if not chunk:
				break

			pending += chunk.decode("utf-8", errors="replace")
			# Both terminators split a line. A bare \r is how git redraws a
			# progress meter in place, so treating it as a line boundary turns
			# "Receiving objects: 43%" into visible progress rather than silence.
			parts = _LINE_BREAK.split(pending)
			pending = parts.pop()
			for part in parts:
				if part.strip():
					on_line(part.rstrip())
		if pending.strip():
			on_line(pending.rstrip())
	finally:
		watchdog.cancel()
		finished.set()
		if proc.stdout:
			proc.stdout.close()
		try:
			proc.wait(timeout=30)
		except subprocess.TimeoutExpired:
			_kill_group(proc)
			proc.wait(timeout=10)

	if timed_out.is_set():
		on_line(f"--- timed out after {timeout}s; process group terminated ---")

	return (proc.returncode if proc.returncode is not None else -1), timed_out.is_set()


def _kill_group(proc: subprocess.Popen, grace: float = 10.0) -> None:
	"""Kill the whole process group, not just the child we spawned.

	bench shells out to git, uv and pip; terminating the wrapper alone leaves
	those running and still holding the bench directory. `start_new_session=True`
	at spawn is what makes the group addressable here.

	Uses `poll()` rather than `wait()` deliberately. This runs on the watchdog
	THREAD while the main thread is blocked reading stdout and will itself call
	`wait()` afterwards — two threads calling `wait()` on one Popen race to reap
	the child, and the loser can block or raise. `poll()` is non-blocking and
	CPython guards the actual reap with an internal lock, so it is safe from
	both.
	"""
	try:
		pgid = os.getpgid(proc.pid)
	except OSError:
		return  # already reaped

	for sig in (signal.SIGTERM, signal.SIGKILL):
		try:
			os.killpg(pgid, sig)
		except OSError:
			return  # group is gone

		deadline = time.monotonic() + grace
		while time.monotonic() < deadline:
			if proc.poll() is not None:
				return
			time.sleep(0.1)


# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------


def reap_stale_requests() -> dict:
	"""Close out jobs whose worker is gone.

	A worker can die between picking a job up and finishing it — OOM killer, a
	restarted supervisor, a `bench restart` during a deploy. Nothing else
	notices: the row says Running, the dock spins forever, and the lock file
	stays behind so the next attempt on that bench is refused too.

	For a restore it is worse than cosmetic. The database root password is
	cleared in finish(), and a worker that was killed never reaches it — so the
	credential sits in the record until something clears it. That something is
	this.

	Deliberately generous. A job is only presumed dead once it is past its own
	timeout by a wide margin, because killing a live job that was merely slow
	would be far worse than leaving a dead one for another five minutes.
	"""
	settings = get_settings()
	limit = settings.get_install_timeout() + STALE_GRACE_SECONDS
	cutoff = frappe.utils.add_to_date(frappe.utils.now_datetime(), seconds=-limit)

	stale = frappe.get_all(
		"App Install Request",
		filters={"status": ["in", ("Running", "Queued")], "modified": ["<", cutoff]},
		fields=["name", "status", "operation", "started_at"],
	)

	closed = []
	for row in stale:
		try:
			request = frappe.get_doc("App Install Request", row.name)
			request.db_set(
				{
					"status": "Failed",
					"exit_code": NEVER_RAN,
					"finished_at": frappe.utils.now_datetime(),
					"error_summary": (
						f"Stopped reporting. This was still marked {row.status} more than "
						f"{limit // 60} minutes after it should have finished, so its worker is "
						"presumed dead. Whether the command itself completed is unknown — check "
						"the bench before re-running."
					),
				},
				update_modified=False,
			)
			if request.is_restore():
				request.clear_restore_secrets()
			frappe.cache.delete_value(CANCEL_KEY.format(name=row.name))
			closed.append(row.name)
		except Exception:
			frappe.logger("server").warning(f"could not reap {row.name}", exc_info=True)

	if closed:
		frappe.db.commit()
		frappe.logger("server").info(f"reaped stale install requests: {', '.join(closed)}")
	return {"checked": len(stale), "closed": closed}


def _plan_for(request) -> list:
	"""The steps this request will run through, decided before it starts."""
	if request.is_command():
		command = commands.get(request.bench_command or "")
		return step_plan.for_command(command.label if command else "Run the command")
	if request.is_ssl():
		return step_plan.for_ssl(request.ssl_mode_key(), bool(request.ssl_dry_run))
	if request.is_restore():
		return step_plan.for_restore(bool(request.restore_backup_first))
	if request.is_pull():
		return step_plan.for_pull()
	return step_plan.for_clone(bool(request.install_on_site))


def run_install_request(name: str) -> dict:
	"""Execute one App Install Request — a clone or a pull.

	Never raises out to the worker: a failure has to end up on the record, not
	only in an error log nobody opens.
	"""
	request = frappe.get_doc("App Install Request", name)
	settings = get_settings()
	buffer: list[str] = []
	last_emit = [0.0]
	last_steps = [0.0]

	plan = step_plan.Plan(_plan_for(request))

	def push_steps(force: bool = False) -> None:
		"""Persist and broadcast the plan.

		Throttled like the log is. A step change is worth showing immediately;
		the output accumulating inside a step is not worth a write per line.
		"""
		now = time.monotonic()
		if not force and now - last_steps[0] < STREAM_INTERVAL:
			return
		last_steps[0] = now
		payload = plan.as_list()
		request.db_set("steps", json.dumps(payload), update_modified=False)
		frappe.db.commit()
		frappe.publish_realtime(
			STEP_EVENT, {"name": name, "steps": payload}, doctype="App Install Request", docname=name
		)

	def should_cancel() -> bool:
		return bool(frappe.cache.get_value(CANCEL_KEY.format(name=name)))

	def step(key: str) -> None:
		plan.start(key)
		push_steps(force=True)

	def emit(line: str) -> None:
		buffer.append(line)
		plan.line(line)
		now = time.monotonic()
		if now - last_emit[0] >= STREAM_INTERVAL:
			last_emit[0] = now
			frappe.publish_realtime(
				LOG_EVENT, {"name": name, "line": line}, doctype="App Install Request", docname=name
			)
			push_steps()
		if len(buffer) % PERSIST_EVERY_LINES == 0:
			request.append_output("\n".join(buffer))
			frappe.db.commit()

	def finish(status: str, exit_code: int | None = None, error: str | None = None) -> dict:
		started = request.started_at

		# A cancelled job reports as cancelled, not as a failure. Both arrive
		# here as a non-zero exit — the process really was killed — but "you
		# stopped this" and "this broke" are different things to be told, and
		# only one of them is worth investigating.
		if status == "Failed" and should_cancel():
			status = "Cancelled"
			error = (
				"Cancelled. The command was stopped part way through, so whatever it had already "
				"done is still done — check the steps above for how far it got."
			)
		frappe.cache.delete_value(CANCEL_KEY.format(name=name))

		if status in ("Success", "Completed With Warnings"):
			plan.succeed()
			plan.abandon("Not needed.")
		else:
			plan.abandon(error or "Stopped here.")
		push_steps(force=True)
		request.db_set(
			{
				"status": status,
				"exit_code": NEVER_RAN if exit_code is None else exit_code,
				"finished_at": frappe.utils.now_datetime(),
				"duration": frappe.utils.time_diff_in_seconds(frappe.utils.now_datetime(), started)
				if started
				else 0,
				"output": "\n".join(buffer),
				"steps": json.dumps(plan.as_list()),
				"error_summary": (error or _tail(buffer))[:1000] or None,
			},
			update_modified=False,
		)
		if request.is_restore():
			# Every terminal path runs through here, so this is the one place
			# the credentials cannot escape by way of an early return.
			request.clear_restore_secrets()
		frappe.db.commit()
		frappe.publish_realtime(
			DONE_EVENT,
			{"name": name, "status": status, "exit_code": exit_code},
			doctype="App Install Request",
			docname=name,
		)
		return {"name": name, "status": status, "exit_code": exit_code, "error": error}

	try:
		bench_doc = frappe.get_doc("Server Bench", request.bench)
		request.db_set(
			{
				"status": "Running",
				"started_at": frappe.utils.now_datetime(),
				"output": "",
				"error_summary": None,
			},
			update_modified=False,
		)
		frappe.db.commit()

		step("check")
		try:
			for note in _preflight(request, bench_doc, settings, on_step=step):
				emit(note)
		except InstallAborted as abort:
			emit(f"refused: {abort}")
			return finish("Failed", exit_code=None, error=str(abort))
		except frappe.ValidationError as abort:
			emit(f"refused: {abort}")
			return finish("Failed", exit_code=None, error=str(abort))
		plan.succeed("check")
		plan.succeed("access")

		env = settings.get_bench_env()
		timeout = settings.get_install_timeout()

		# Scoped to this bench, so two different benches can install in
		# parallel while one bench never sees concurrent get-app calls.
		try:
			with filelock(f"server_bench_install::{bench_doc.name}", timeout=5, is_global=True):
				if request.is_command():
					step("run")
					command = commands.get(request.bench_command)
					argv = commands.build_argv(
						command,
						settings.bench_executable,
						request.install_on_site or None,
						json.loads(request.command_params or "{}"),
					)
					request.db_set("command", " ".join(argv), update_modified=False)
					frappe.db.commit()
					emit(f"$ {' '.join(argv)}")

					# The catalogue carries its own timeout: a clear-cache should
					# not inherit the hour a bench update legitimately needs.
					code, timed_out = _stream(argv, bench_doc.bench_path, env, command.timeout, emit, should_cancel)
					if code != 0:
						return finish(
							"Failed",
							exit_code=code,
							error=_explain_failure(
								code, timed_out, command.timeout, request, f"bench {command.label.lower()}"
							),
						)
				elif request.is_ssl():
					step("issue" if request.ssl_mode_key() == ssl.MODE_ISSUE else "renew")
					argv = ssl.build_argv(
						request.ssl_mode_key(),
						settings.bench_executable,
						request.install_on_site or None,
						request.ssl_domain or None,
						bool(request.ssl_dry_run),
					)
					request.db_set("command", " ".join(argv), update_modified=False)
					frappe.db.commit()
					emit(f"$ {' '.join(argv)}")

					code, timed_out = _stream(argv, bench_doc.bench_path, env, ssl.SSL_TIMEOUT, emit, should_cancel)
					if code != 0:
						return finish(
							"Failed",
							exit_code=code,
							error=_explain_failure(
								code, timed_out, ssl.SSL_TIMEOUT, request, "the SSL command"
							),
						)

					# bench reports several SSL failures by printing and then
					# exiting 0. Trusting the exit code alone would record
					# "Success" for a site still on plain HTTP.
					quiet = ssl.quiet_failure(request.output or "")
					if quiet:
						return finish("Failed", exit_code=code, error=quiet)
				elif request.is_restore():
					site = request.install_on_site
					backup = request.resolve_backup(bench_doc.bench_path)

					if request.restore_backup_first:
						step("safety")
						# Files are only worth backing up when files are about
						# to be overwritten; a dump is fast, a files tar is not.
						with_files = bool(request.restore_public_files or request.restore_private_files)
						safety = restore.build_backup_argv(settings.bench_executable, site, with_files)
						emit(f"$ {' '.join(safety)}")
						code, timed_out = _stream(safety, bench_doc.bench_path, env, timeout, emit, should_cancel)
						if code != 0:
							# Refuse to continue. The backup is the only thing
							# standing between a bad restore and lost data, so
							# failing to take one is a reason to stop, not a
							# warning to print on the way past.
							return finish(
								"Failed",
								exit_code=code,
								error=(
									"The safety backup failed, so nothing was restored and the site "
									"is untouched. "
									+ _explain_failure(code, timed_out, timeout, request, "bench backup")
								),
							)
						emit("")

					step("restore")
					argv = restore.build_argv(
						settings.bench_executable,
						site,
						backup,
						request.get_password("restore_db_password", raise_exception=False),
						request.restore_db_username or None,
						request.get_password("restore_encryption_key", raise_exception=False),
						bool(request.restore_public_files),
						bool(request.restore_private_files),
					)
					# Stored and streamed redacted. The real argv never reaches
					# the database or the browser.
					shown = " ".join(restore.redact(argv))
					request.db_set("command", shown, update_modified=False)
					frappe.db.commit()
					emit(f"$ {shown}")

					code, timed_out = _stream(argv, bench_doc.bench_path, env, timeout, emit, should_cancel)
					if code != 0:
						return finish(
							"Failed",
							exit_code=code,
							error=_explain_failure(code, timed_out, timeout, request, "bench restore"),
						)
				elif request.is_pull():
					step("pull")
					app = scanner.read_app(request.app_path)
					argv = build_pull_argv(request, app)
					request.db_set("command", " ".join(argv), update_modified=False)
					# Commit immediately. Without this the command sits in an
					# uncommitted transaction for the whole run, so the dock has
					# nothing to show while the work is actually happening.
					frappe.db.commit()
					emit(f"$ cd {request.app_path}")
					emit(f"$ {' '.join(argv)}")

					# cwd is the APP, not the bench: git has to run inside the
					# checkout it is updating.
					code, timed_out = _stream(argv, request.app_path, env, timeout, emit, should_cancel)
					if code != 0:
						return finish(
							"Failed",
							exit_code=code,
							error=_explain_failure(code, timed_out, timeout, request, "git pull"),
						)
				else:
					step("clone")
					argv = build_get_app_argv(request, settings)
					request.db_set("command", " ".join(argv), update_modified=False)
					frappe.db.commit()
					emit(f"$ {' '.join(argv)}")

					code, timed_out = _stream(argv, bench_doc.bench_path, env, timeout, emit, should_cancel)
					if code != 0:
						# Ask the FILESYSTEM whether the work happened, rather than
						# trusting the exit code alone. This is not string-matching
						# the log to decide success — the app either landed on disk
						# at the branch that was asked for, or it did not.
						landed = _clone_landed(request)
						benign = landed and _SUPERVISOR_POSTSTEP.search("\n".join(buffer[-60:]))
						if benign:
							emit("")
							emit(
								"[note] The app was cloned and installed. bench then exited "
								f"{code} because its final step runs `sudo supervisorctl status`, "
								"which needs a password on this host. Nothing about the install is "
								"affected."
							)
							return finish(
								"Completed With Warnings",
								exit_code=code,
								error=(
									"Installed successfully. bench's own post-step failed: it runs "
									"`sudo supervisorctl status` to decide whether to restart "
									"processes, and this host has no passwordless sudo. Do not re-run "
									"this — the app is already in place."
								),
							)
						return finish(
							"Failed",
							exit_code=code,
							error=_explain_failure(code, timed_out, timeout, request, "bench get-app"),
						)

					if request.install_on_site:
						step("install")
						argv = build_install_app_argv(request, settings)
						emit("")
						emit(f"$ {' '.join(argv)}")
						# Unpack both values. This used to assign the whole
						# (code, timed_out) tuple to `code`, so the comparison
						# below was always true and a successful install-app was
						# reported as a failure every single time.
						code, timed_out = _stream(argv, bench_doc.bench_path, env, timeout, emit, should_cancel)
						if code != 0:
							return finish(
								"Failed",
								exit_code=code,
								error=_explain_failure(
									code, timed_out, timeout, request, "bench install-app"
								),
							)
		except LockTimeoutError:
			message = f"Another install is already running on {bench_doc.name}. Try again when it finishes."
			emit(f"[lock] {message}")
			return finish("Failed", error=message)

		# Before finish(), so the step is recorded as work rather than closed
		# out as "did not run".
		if plan.get("rescan"):
			step("rescan")
		try:
			from server.bench import discovery

			discovery.scan_benches()
			emit("Bench re-read from disk.")
		except Exception as exc:
			# A stale app list is a cosmetic problem; the operation itself
			# already succeeded. Say so and carry on.
			frappe.logger("server").warning("post-install rescan failed", exc_info=True)
			emit(f"Could not re-read the bench: {exc}")
			plan.fail("rescan", "The operation succeeded; only the refresh failed.")

		return finish("Success", exit_code=0)

	except Exception as exc:
		frappe.db.rollback()
		frappe.logger("server").error(f"install request {name} failed: {exc}", exc_info=True)
		emit(f"[error] {type(exc).__name__}: {exc}")
		try:
			return finish("Failed", error=f"{type(exc).__name__}: {exc}")
		except Exception:
			# Last resort: record the status without touching anything that
			# could fail again, so a bookkeeping error can never leave a job
			# stuck showing "Running" forever.
			frappe.db.rollback()
			frappe.db.set_value(
				"App Install Request",
				name,
				{"status": "Failed", "error_summary": f"{type(exc).__name__}: {exc}"[:1000]},
				update_modified=False,
			)
			frappe.db.commit()
			return {"name": name, "status": "Failed", "error": str(exc)}


def _clone_landed(request) -> bool:
	"""Is the app actually on disk, as a checkout of the branch that was asked for?

	The outcome check that lets a non-zero exit still be reported honestly. It
	deliberately looks at the filesystem rather than the log: bench's exit code
	answers "did the command end cleanly", which is a different question from
	"is the app installed".
	"""
	try:
		app = scanner.read_app(request.app_path)
	except Exception:
		return False
	if not app.git_url:
		return False
	if request.branch and app.branch and app.branch != request.branch:
		return False
	return True


def _explain_failure(code: int, timed_out: bool, timeout: int, request, what: str) -> str:
	"""Name the actual cause rather than echoing an exit code.

	Order matters, and getting it wrong is not harmless. A timeout must be
	reported as a timeout BEFORE any guess about branch divergence: a real
	erpnext pull was killed by the watchdog at thirty minutes and the operator
	was told the branch had diverged, which is a completely different problem
	with a completely different fix.
	"""
	if timed_out:
		return (
			f"{what} was still running after {timeout}s and was terminated. Pulling or cloning a "
			"large repository can legitimately take longer, especially a shallow checkout "
			"(bench clones with --depth 1), where git may have to fetch a great deal of history. "
			"Raise Install Timeout in Server Settings and try again, or run the command by hand."
		)

	if code < 0:
		return f"{what} was killed by signal {abs(code)} before it finished."

	if what == "git pull" and not request.allow_merge:
		return (
			f"{what} exited {code}. The most likely cause is that the branch has diverged from the "
			"remote, which --ff-only refuses rather than merging. Check the log: if a merge is "
			"genuinely what you want, tick 'Allow Merge Commit' and run it again."
		)

	return f"{what} exited {code}."


def _tail(lines: list[str], count: int = 12) -> str:
	return "\n".join(lines[-count:])


def enqueue_install_request(name: str) -> str:
	"""Queue a request. Returns the job id."""
	job_id = f"server::app_install::{name}"
	frappe.enqueue(
		"server.bench.installer.run_install_request",
		queue="long",
		# The queue's own 1500s default is not enough for a cold clone plus a
		# pip install of a large app.
		timeout=get_settings().get_install_timeout() + 180,
		job_id=job_id,
		deduplicate=True,
		enqueue_after_commit=True,
		name=name,
	)
	return job_id
