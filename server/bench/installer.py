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

import os
import signal
import subprocess
import threading
import time

import frappe
from frappe.utils.synchronization import LockTimeoutError, filelock

from server.bench import doctor, scanner
from server.server.doctype.server_settings.server_settings import get_settings

#: How often, at most, to push log lines to a watching browser.
STREAM_INTERVAL = 0.25

#: How often to flush the accumulated log to the database, so a crash still
#: leaves a usable trail rather than an empty Output field.
PERSIST_EVERY_LINES = 40

LOG_EVENT = "server:app_install_log"
DONE_EVENT = "server:app_install_done"

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


def _preflight(request, bench_doc, settings) -> list[str]:
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

	if request.is_pull():
		return _preflight_pull(request)
	return _preflight_clone(request, bench_doc)


def _preflight_clone(request, bench_doc) -> list[str]:
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
	# with a message that blames the repository for not existing.
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


def _stream(argv: list[str], cwd: str, env: dict, timeout: int, on_line) -> int:
	"""Run a command, streaming combined output line by line. Returns the exit code.

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
		text=True,
		bufsize=1,
		start_new_session=True,
	)

	timed_out = threading.Event()

	def _on_deadline():
		timed_out.set()
		_kill_group(proc)

	watchdog = threading.Timer(timeout, _on_deadline)
	watchdog.daemon = True
	watchdog.start()

	try:
		for line in proc.stdout:
			on_line(line.rstrip("\n"))
	finally:
		watchdog.cancel()
		if proc.stdout:
			proc.stdout.close()
		try:
			proc.wait(timeout=30)
		except subprocess.TimeoutExpired:
			_kill_group(proc)
			proc.wait(timeout=10)

	if timed_out.is_set():
		on_line(f"--- timed out after {timeout}s; process group terminated ---")

	return proc.returncode if proc.returncode is not None else -1


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


def run_install_request(name: str) -> dict:
	"""Execute one App Install Request — a clone or a pull.

	Never raises out to the worker: a failure has to end up on the record, not
	only in an error log nobody opens.
	"""
	request = frappe.get_doc("App Install Request", name)
	settings = get_settings()
	buffer: list[str] = []
	last_emit = [0.0]

	def emit(line: str) -> None:
		buffer.append(line)
		now = time.monotonic()
		if now - last_emit[0] >= STREAM_INTERVAL:
			last_emit[0] = now
			frappe.publish_realtime(
				LOG_EVENT, {"name": name, "line": line}, doctype="App Install Request", docname=name
			)
		if len(buffer) % PERSIST_EVERY_LINES == 0:
			request.append_output("\n".join(buffer))
			frappe.db.commit()

	def finish(status: str, exit_code: int | None = None, error: str | None = None) -> dict:
		started = request.started_at
		request.db_set(
			{
				"status": status,
				"exit_code": NEVER_RAN if exit_code is None else exit_code,
				"finished_at": frappe.utils.now_datetime(),
				"duration": frappe.utils.time_diff_in_seconds(frappe.utils.now_datetime(), started)
				if started
				else 0,
				"output": "\n".join(buffer),
				"error_summary": (error or _tail(buffer))[:1000] or None,
			},
			update_modified=False,
		)
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

		try:
			for note in _preflight(request, bench_doc, settings):
				emit(f"[preflight] {note}")
		except InstallAborted as abort:
			emit(f"[preflight] refused: {abort}")
			return finish("Failed", exit_code=None, error=str(abort))
		except frappe.ValidationError as abort:
			emit(f"[preflight] refused: {abort}")
			return finish("Failed", exit_code=None, error=str(abort))

		env = settings.get_bench_env()
		timeout = settings.get_install_timeout()

		# Scoped to this bench, so two different benches can install in
		# parallel while one bench never sees concurrent get-app calls.
		try:
			with filelock(f"server_bench_install::{bench_doc.name}", timeout=5, is_global=True):
				if request.is_pull():
					app = scanner.read_app(request.app_path)
					argv = build_pull_argv(request, app)
					request.db_set("command", " ".join(argv), update_modified=False)
					emit(f"$ cd {request.app_path}")
					emit(f"$ {' '.join(argv)}")

					# cwd is the APP, not the bench: git has to run inside the
					# checkout it is updating.
					code = _stream(argv, request.app_path, env, timeout, emit)
					if code != 0:
						return finish(
							"Failed",
							exit_code=code,
							error=_explain_pull_failure(code, request),
						)
				else:
					argv = build_get_app_argv(request, settings)
					request.db_set("command", " ".join(argv), update_modified=False)
					emit(f"$ {' '.join(argv)}")

					code = _stream(argv, bench_doc.bench_path, env, timeout, emit)
					if code != 0:
						return finish("Failed", exit_code=code, error=f"bench get-app exited {code}")

					if request.install_on_site:
						argv = build_install_app_argv(request, settings)
						emit("")
						emit(f"$ {' '.join(argv)}")
						code = _stream(argv, bench_doc.bench_path, env, timeout, emit)
						if code != 0:
							return finish("Failed", exit_code=code, error=f"bench install-app exited {code}")
		except LockTimeoutError:
			message = f"Another install is already running on {bench_doc.name}. Try again when it finishes."
			emit(f"[lock] {message}")
			return finish("Failed", error=message)

		result = finish("Success", exit_code=0)

		# Refresh the bench so its app list reflects what just landed.
		try:
			from server.bench import discovery

			discovery.scan_benches()
		except Exception:
			frappe.logger("server").warning("post-install rescan failed", exc_info=True)

		return result

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


def _explain_pull_failure(code: int, request) -> str:
	"""Name the likely cause rather than echoing an exit code.

	A non-fast-forward is by far the most common way a pull fails on a bench,
	and "git pull exited 1" tells nobody what to do about it.
	"""
	if not request.allow_merge:
		return (
			f"git pull exited {code}. The most likely cause is that the branch has diverged from "
			"the remote, which --ff-only refuses rather than merging. Check the log: if a merge is "
			"genuinely what you want, tick 'Allow Merge Commit' and run it again."
		)
	return f"git pull exited {code}."


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
