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

from server.bench import commands, doctor, node, restore, scanner, siteconfig, ssl
from server.bench import steps as step_plan
from server.server.doctype.server_settings.server_settings import get_settings

#: How often, at most, to push log lines to a watching browser.
STREAM_INTERVAL = 0.25

#: How often to flush the accumulated log to the database, so a crash still
#: leaves a usable trail rather than an empty Output field.
PERSIST_EVERY_LINES = 200

#: …or this many seconds, whichever comes first. A chatty job (git progress is
#: split on bare carriage returns, so each redraw is its own line) would
#: otherwise spend more time on database round-trips than on the command, and a
#: quiet one would leave nothing persisted for minutes at a time.
PERSIST_EVERY_SECONDS = 3.0

#: How much of the log is kept in memory. Only the tail is ever needed after
#: the fact — for the error summary, and for the markers bench prints at the end
#: of a quiet SSL failure. The whole log lives in the `output` column.
TAIL_LINES = 400

#: How often a running job checks whether someone asked it to stop.
CANCEL_POLL_SECONDS = 2.0

#: Give up polling only after this many consecutive failures — about ten
#: minutes. Long enough that a redis restart does not cost the feature, bounded
#: so a permanently broken check does not spin for hours.
CANCEL_FAILURE_LIMIT = 300

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

#: A queued job waits behind whatever is running, and the default bench has one
#: `long` worker — so hours of waiting is normal. A full day is not.
QUEUED_ABANDONED_SECONDS = 86400

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

	# A Provision request is the one shape with no bench to check: it is
	# building the bench. Everything else acts on one that already exists, and
	# the usability check is re-run here rather than trusted from validate
	# time because a directory can disappear between the two.
	if bench_doc is not None:
		bench_doc.assert_usable()

	if request.is_provision():
		return _preflight_provision(request, settings)

	if not request.app_name:
		raise InstallAborted("No app name could be derived from the source.")

	bench_exe = (settings.bench_executable or "").strip()
	if not bench_exe.startswith("/"):
		raise InstallAborted("Bench Executable must be an absolute path — workers do not inherit your PATH.")
	if not os.path.isfile(bench_exe) or not os.access(bench_exe, os.X_OK):
		raise InstallAborted(f"{bench_exe} is not an executable file.")

	# Assets are built by node, and the node the shell defaults to is not
	# necessarily the one this bench's frappe accepts. Refuse here rather than
	# discovering it from a SyntaxError inside a dependency, minutes into a
	# clone that had otherwise worked.
	# Clone only: a pull is `git pull` in the app directory and never reaches
	# node, and every other operation is further from it still.
	if request.is_clone() and not request.skip_assets:
		_assert_node_is_usable(bench_doc.bench_path, None)

	if request.is_command():
		return _preflight_command(request, bench_doc)
	if request.is_console():
		return _preflight_console(request)
	if request.is_ssl():
		return _preflight_ssl(request, bench_doc)
	if request.is_restore():
		return _preflight_restore(request, bench_doc)
	if request.is_pull():
		return _preflight_pull(request)
	return _preflight_clone(request, bench_doc, on_step)


def _assert_node_is_usable(bench_path: str | None, frappe_version: str | None) -> None:
	"""Stop now if the assets step is going to fail for want of a node.

	Only when we POSITIVELY established that what will run is too old. A node
	we could not identify is not a refusal — this app runs on machines whose
	toolchain it did not install, and refusing on an unknown would be this
	check inventing a failure rather than reporting one.
	"""
	_, choice = node.activate(os.environ.copy(), node.required_major(bench_path, frappe_version))
	if not choice.satisfied:
		raise InstallAborted(choice.note)


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


def _app_landed(bench_path: str, app_name: str, branch: str = "") -> bool:
	"""Is the app actually checked out, whatever `get-app` exited with?

	The provisioning equivalent of `_clone_landed`, which cannot be reused
	directly because that one reads `request.app_path` — a Provision request
	has many apps and none of them is `app_name`.
	"""
	try:
		app = scanner.read_app(os.path.join(bench_path, "apps", app_name))
	except Exception:  # noqa: BLE001
		return False
	if not app.git_url:
		return False
	if branch and app.branch and app.branch != branch:
		return False
	return True


def _provision_git_url(profile_name: str, repo: str) -> str:
	"""The clone URL for an app, from the GitHub Profile that owns it.

	Resolved here rather than stored on the request so a profile whose SSH
	alias changed since the request was queued still clones correctly.
	"""
	if not profile_name or not frappe.db.exists("GitHub Profile", profile_name):
		# A bare repo name with no profile is treated as a plain git URL, which
		# is what somebody pasting one would expect.
		return repo
	return frappe.get_doc("GitHub Profile", profile_name).git_url(repo)


def _provision_domain(request, bench_path: str, site: str) -> list[str]:
	"""Write the DNS record and report what is still manual.

	Never raises and never fails the job. The bench and the site are built by
	this point, and a registrar having a bad afternoon is not a reason to
	report that as a failure — it is a reason to say which step is left.
	"""
	notes = []
	try:
		from server.server.doctype.domain_provider.domain_provider import DomainProvider  # noqa: F401

		result = frappe.call(
			"server.api.point_domain_at_this_host",
			name=request.provision_domain_provider,
			domain=request.provision_domain,
			confirm=request.provision_domain,
		)
	except Exception as exc:  # noqa: BLE001
		notes.append(f"Could not write the DNS record: {exc}")
		result = {"ok": False}

	if result.get("ok"):
		notes.append(
			f"{request.provision_domain} now points at {result.get('address')} "
			f"(zone {result.get('zone')})."
		)
	elif result.get("error"):
		notes.append(f"DNS was not written: {result['error']}")

	# The half everybody forgets. A record alone does not make frappe serve the
	# name, and two of the remaining steps need root this app does not have.
	if site:
		notes.append(
			"Still to do, and these need root: "
			f"bench setup add-domain --site {site} {request.provision_domain}; "
			"bench config dns_multitenant on; bench setup nginx --yes; "
			"sudo bench setup reload-nginx"
		)
	return notes


def _site_exists_on_disk(bench_doc, site: str) -> bool:
	"""Whether the site directory is actually there.

	NOT `bench_doc.site_names()`, which comes from the last scan and is stale
	the moment anything creates a site — including a previous attempt of this
	same job that died partway. `bench new-site` writes the site directory
	before it finishes, so a run that failed at the last step leaves a site
	that the scan does not know about and that `new-site` will then refuse to
	create again. Asking the filesystem is the only answer that is true now.
	"""
	if not site:
		return False
	return os.path.isdir(os.path.join(bench_doc.bench_path, "sites", site))


def _create_site_for_restore(request, bench_doc, settings, env, step, emit, finish, should_cancel):
	"""Make an empty site for the dump to land in.

	`bench restore` loads into an EXISTING site and will not create one, so
	pulling a site onto a machine that has never had it needs this first —
	which is nearly every site in a migration.

	It reuses the database root password the restore already required, so this
	asks for nothing extra. The site is created with no apps: `bench restore`
	replaces the database wholesale a moment later, so installing anything here
	would be work thrown away.
	"""
	from server.bench import provision

	site = request.install_on_site
	step("create")
	emit(f"{site} is not on this bench yet — creating it for the dump to land in.")

	# Generated rather than omitted: `bench new-site` prompts for it when the
	# flag is absent, and stdin is closed. It is replaced by the dump a moment
	# later, but it is printed below because if the restore then fails this is
	# the only way into the site that was just created.
	admin_password = provision.generate_admin_password()
	argv = provision.build_new_site_argv(
		settings.bench_executable,
		site,
		request.get_password("restore_db_password", raise_exception=False) or "",
		admin_password=admin_password,
	)
	# `--set-default` belongs to a bench's FIRST site, not to a site being
	# restored alongside others. Dropped here so a migration does not silently
	# change which site the bench serves by default.
	argv = [a for a in argv if a != "--set-default"]

	shown = " ".join(restore.redact(argv))
	emit(f"$ {shown}")

	# Kept so the failure can be explained specifically. `emit` writes to the
	# job log and returns nothing, so the only way to know WHY new-site refused
	# is to watch the lines going past.
	said: list[str] = []

	def watch(line: str) -> None:
		said.append(line)
		emit(line)

	code, timed_out = _stream(
		argv, bench_doc.bench_path, env, settings.get_install_timeout(), watch, should_cancel
	)
	if code != 0:
		explanation = _explain_failure(
			code, timed_out, settings.get_install_timeout(), request, "bench new-site"
		)
		# The specific one worth naming. An earlier attempt that died partway
		# leaves the site directory behind, and `new-site` then refuses — which
		# reads as "it is already there, why did you try" rather than "clear up
		# the wreckage of the last attempt".
		if any("already exists" in line.lower() for line in said):
			explanation = (
				f"{site} already exists on this bench, so it was not created. If it is left over "
				f"from an attempt that failed, remove it first: "
				f"bench --site {site} drop-site --db-root-password ... — this app will not drop a "
				f"database as a side effect of creating one."
			)
		return finish("Failed", exit_code=code, error=explanation)

	emit(
		f"Administrator password for the empty site is {admin_password} — the restore replaces it "
		f"with whatever the dump carries, so this only matters if the restore does not finish."
	)

	# The site list on the document is stale the moment the site is made, and
	# the restore checks it again.
	bench_doc.reload()
	emit("")
	return None


def _pull_from_remote(request, bench_doc, step, emit, finish):
	"""Ask the other server for a fresh backup, then bring it here.

	Returns None when the files are on disk and the request has been pointed at
	them, or a `finish(...)` when it could not be done. Everything after this
	is the ordinary Chosen Files restore — which is the point: a pulled backup
	takes exactly the same path as one picked by hand, so there is no second
	notion of what a restorable set is.
	"""
	import os

	from server.remote import transfer

	server = frappe.get_doc("Managed Server", request.restore_remote_server)
	source_bench = request.restore_remote_bench
	source_site = request.restore_remote_site
	client = server.client()

	step("prepare")
	emit(f"Asking {server.server_name} to back up {source_site} on {source_bench}…")
	emit("A fresh backup, not the newest existing one — moving a site means moving it as it is now.")

	prepared = client.call(
		"server.api.prepare_backup_for_transfer",
		{"bench": source_bench, "site": source_site, "with_files": 1},
		# A backup of a large site is minutes of work on the other machine.
		timeout=max(900, get_settings().get_install_timeout()),
	)
	if not prepared.ok:
		return finish("Failed", exit_code=None, error=f"{server.server_name}: {prepared.error}")

	backup = (prepared.message or {}).get("backup") or {}
	emit(f"{server.server_name} made {backup.get('key') or 'a backup'} ({backup.get('size_text') or '?'}).")

	directory = os.path.join(bench_doc.bench_path, "backups")
	os.makedirs(directory, exist_ok=True)

	try:
		wanted = transfer.plan(
			backup,
			directory,
			want_public=bool(request.restore_public_files),
			want_private=bool(request.restore_private_files),
		)
		transfer.check_room(directory, wanted)
	except transfer.TransferRefused as refused:
		return finish("Failed", exit_code=None, error=str(refused))

	step("fetch")
	emit(f"Pulling {transfer.describe(wanted)} into {directory}")

	for item in wanted:
		last = [0.0]

		def report(progress, part=item.part):
			# Throttled to the same quarter second the log stream uses; a
			# progress line per chunk on a multi-gigabyte file is thousands of
			# rows nobody reads.
			now = time.time()
			if now - last[0] < 1.0 and progress.received < progress.total:
				return
			last[0] = now
			emit(f"  {part}: {progress.percent:.0f}% ({progress.received:,} of {progress.total:,} bytes)")

		try:
			result = client.download(
				"server.api.download_backup_file",
				{
					"bench": source_bench,
					"site": source_site,
					"key": backup.get("key"),
					"part": item.part,
				},
				item.destination,
				expected_size=item.size,
				on_progress=report,
			)
		except Exception as exc:  # noqa: BLE001
			# The partial file is left where it is: a second attempt resumes
			# from it rather than starting the gigabytes again.
			return finish(
				"Failed",
				exit_code=None,
				error=f"Copying the {item.part} file stopped: {exc}. Running this again resumes it.",
			)

		emit(f"  {item.part}: {result.received:,} bytes" + (" (resumed)" if result.resumed_from else ""))

	# Point the request at what was pulled, and let the ordinary path take over.
	by_part = {item.part: item.destination for item in wanted}
	request.db_set(
		{
			"restore_source": "Chosen Files",
			"restore_database_file": by_part.get("database"),
			"restore_public_file": by_part.get("public"),
			"restore_private_file": by_part.get("private"),
		},
		update_modified=False,
	)
	request.reload()
	frappe.db.commit()
	emit("")
	return None


def _preflight_provision(request, settings) -> list[str]:
	"""Answer everything before four gigabytes are spent on a clone.

	The checks themselves live in the frappe-free `provision.preflight`, which
	returns the same `ssl.Check` rows the SSL readiness panel uses. Anything
	blocking that failed stops the run here, with the check's own detail as the
	message — those are written to name the command that fixes them.
	"""
	from server.bench import provision

	root = settings.get_bench_root()
	checks = provision.preflight(
		bench_root=root,
		bench_name=request.provision_bench_name,
		site_name=request.provision_site_name or "",
		db_root_password=request.get_password("provision_db_password", raise_exception=False) or "",
		frappe_version=str(request.provision_frappe_version or "16"),
		skip_assets=bool(request.provision_skip_assets),
	)

	failed = [check for check in checks if check.blocking and not check.ok]
	if failed:
		raise InstallAborted("; ".join(f"{check.label}: {check.detail}" for check in failed))

	# There is no bench to ask yet, so the requested frappe version is the only
	# thing that can name a node major. Only checked when assets are actually
	# going to be built — a bench init with --skip-assets never runs node.
	if not request.provision_skip_assets:
		_assert_node_is_usable(None, str(request.provision_frappe_version or "16"))

	notes = [f"{check.label}: {check.detail}" for check in checks]
	advisory = [check for check in checks if not check.blocking and not check.ok]
	notes += [f"Warning — {check.label}: {check.detail}" for check in advisory]
	return notes


def _preflight_console(request) -> list[str]:
	"""Re-validate the command, and say plainly what will not work.

	The note is not decoration. `stdin` is closed for every job in this app, so
	an interactive program exits immediately — and the operator who typed `top`
	needs to read WHY in the log rather than conclude the feature is broken.
	"""
	from server.bench import console

	try:
		command = console.validate(request.console_command)
	except console.Refusal as exc:
		raise InstallAborted(str(exc)) from exc

	# Deliberately does NOT echo the command — the run step does that, and
	# printing it in both places made the log show it twice.
	del command
	return [
		f"Running in {request.bench} with stdin closed.",
		"Anything interactive (vim, top, mariadb, bench console) will exit straight away.",
	]


def _preflight_restore(request, bench_doc) -> list[str]:
	"""Refuse a restore that cannot work, before the database is dropped.

	The ordering matters: everything that would leave the site broken is
	checked before anything that merely fails.
	"""
	from server.bench import provision

	site = (request.install_on_site or "").strip()
	# A target that is not here yet is CREATED, whatever the source. That was
	# only allowed for a remote pull, which made the obvious safe habit
	# impossible: restore a backup under a temporary name, check it, and only
	# then swap the names over. Restoring over the live site to find out
	# whether the backup is any good is exactly the move worth avoiding.
	if site not in bench_doc.site_names() and not provision.VALID_SITE_NAME.match(site):
		raise InstallAborted(
			f"{site!r} is not a site on {bench_doc.name} and is not a usable name for a new one. "
			"Site names are lowercase letters, digits, dots and hyphens."
		)

	password = request.get_password("restore_db_password", raise_exception=False)

	if remote:
		# Nothing is on disk yet — the files are pulled in the step after this
		# one. What matters here is that the credential is present and the
		# other end answers, both of which are cheap and both of which are
		# worth knowing BEFORE a multi-gigabyte transfer rather than after.
		if not password:
			raise InstallAborted(
				"The database root password is missing. bench restore cannot drop and recreate "
				"the database without it, and there is no terminal here for it to ask on."
			)

		server = frappe.get_doc("Managed Server", request.restore_remote_server)
		check = server.client().verify()
		if not check.ok:
			raise InstallAborted(f"{server.server_name} is not answering: {check.error}")

		notes = [
			f"Restore {site} from {request.restore_remote_site} on {server.server_name}.",
			f"{server.server_name} answered as {check.data.get('hostname', 'itself')}.",
			"A fresh backup will be taken there, pulled here, and only then restored.",
		]
		if not _site_exists_on_disk(bench_doc, site):
			notes.append(f"{site} does not exist on this bench yet and will be created first.")
		return notes

	try:
		backup = request.resolve_backup(bench_doc.bench_path)
	except restore.RestoreRefused as exc:
		raise InstallAborted(str(exc)) from exc

	if not os.path.isfile(backup.database):
		raise InstallAborted(f"{backup.database} is gone. Nothing was changed.")

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
	# Right-backup-wrong-site is compared against the site the backup CAME
	# from, not the site it is going into. Under a rename those differ by
	# design, and comparing against the target would report the deliberate act
	# as the accident this check exists to catch.
	mismatch = restore.describe_mismatch(backup, request.backup_site)
	if mismatch:
		notes.append(mismatch)
	if request.backup_site != site:
		notes.append(f"Restoring {request.backup_site}'s backup into {site}, which is created here.")
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
	try:
		probe = doctor.check_repo(request.resolved_git_url, request.branch or None)
	except doctor.RepoRefused as exc:
		raise InstallAborted(str(exc)) from exc
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
	# Nothing after this can be read as an option, whatever validation upstream
	# does or stops doing.
	argv.append("--")
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
		failures = 0
		while not finished.wait(CANCEL_POLL_SECONDS):
			try:
				if should_cancel():
					on_line("--- cancelled; stopping the process group ---")
					_kill_group(proc)
					return
				failures = 0
			except Exception as exc:  # noqa: BLE001 - a broken check must not kill the job
				# Keep trying. Returning on the first failure is exactly how
				# this went unnoticed: one AttributeError on tick one and the
				# job became uncancellable in silence. A blip in redis should
				# cost one tick, not the feature.
				failures += 1
				if failures == 1 or failures % 30 == 0:
					on_line(f"--- cancel check failed ({type(exc).__name__}: {exc}) ---")
				if failures >= CANCEL_FAILURE_LIMIT:
					on_line("--- cancel checks keep failing; this job can no longer be stopped ---")
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


def _sudo_kill(pgid: int, sig: int) -> bool:
	"""Signal a process group we do not own, via sudo. True if sudo accepted it.

	`sudo -n` so a host without the NOPASSWD rule fails instantly rather than
	waiting on a password prompt no one is there to answer.
	"""
	name = "TERM" if sig == signal.SIGTERM else "KILL"
	try:
		result = subprocess.run(  # noqa: S603
			["sudo", "-n", "kill", f"-{name}", f"-{pgid}"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			timeout=10,
			check=False,
		)
	except (OSError, subprocess.SubprocessError):
		return False
	return result.returncode == 0


def _revive_nginx(emit) -> None:
	"""Put nginx back after an SSL step ended badly.

	Issuance stops nginx to free port 443 and starts it again at the end. Any
	path that skips the end — a non-zero exit, the watchdog, someone pressing
	Stop — leaves every site on the machine offline. This is cheap, safe to run
	when nginx is already up, and the alternative is an outage nobody is told
	about.
	"""
	try:
		result = subprocess.run(  # noqa: S603
			["sudo", "-n", "systemctl", "start", "nginx"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=30,
			check=False,
		)
	except (OSError, subprocess.SubprocessError) as exc:
		emit(f"!! could not restart nginx: {exc}. Sites may be OFFLINE — check the server.")
		return

	if result.returncode == 0:
		emit("nginx restarted (the SSL step stops it and did not finish cleanly).")
	else:
		emit(
			"!! nginx may still be STOPPED and every site offline. "
			f"Run `sudo systemctl start nginx` now. ({(result.stderr or '').strip()[:160]})"
		)


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
		except PermissionError:
			# The group is running as root — `sudo -n certbot` and its children.
			# The worker is not root and may not signal them, and treating that
			# EPERM as "already gone" is how a stalled certbot kept running with
			# nginx stopped while the log said the process had been terminated.
			# The same NOPASSWD rule that permits certbot permits this.
			if _sudo_kill(pgid, sig):
				continue
			return
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
	"""Close out jobs whose worker is gone, and scrub credentials it left behind.

	A worker can die between picking a job up and finishing it — OOM killer, a
	restarted supervisor, a `bench restart` during a deploy. Nothing else
	notices: the row says Running, the dock spins forever, and the lock file
	stays behind so the next attempt on that bench is refused too.

	Age is measured from `started_at`, not `modified`. Every write in the job
	body uses `update_modified=False` on purpose, so `modified` never moves off
	the row's creation time — measuring from it meant measuring age since
	creation, which would have killed a perfectly healthy `bench update` an hour
	into its legitimate two-hour budget.

	Each row is judged against ITS OWN budget too. A restore with a safety
	backup is allowed twice the install timeout, and `bench update` carries
	7200s of its own; one global cutoff would reap the slow ones while they
	were still working.
	"""
	settings = get_settings()
	now = frappe.utils.now_datetime()
	closed = []
	checked = 0

	running = frappe.get_all(
		"App Install Request",
		filters={"status": "Running"},
		fields=["name", "started_at"],
	)
	for row in running:
		checked += 1
		if not row.started_at:
			continue
		request = frappe.get_doc("App Install Request", row.name)
		limit = _worst_case_seconds(request, settings) + STALE_GRACE_SECONDS
		if frappe.utils.time_diff_in_seconds(now, row.started_at) < limit:
			continue
		if _close_stale(request, "Running", limit):
			closed.append(row.name)

	# A queued job legitimately waits behind whatever is running, and the
	# default bench has one `long` worker — so the wait can be hours. Only a row
	# that has sat for a full day is presumed abandoned.
	queued = frappe.get_all(
		"App Install Request",
		filters={
			"status": "Queued",
			"creation": ["<", frappe.utils.add_to_date(now, seconds=-QUEUED_ABANDONED_SECONDS)],
		},
		pluck="name",
	)
	for name in queued:
		checked += 1
		if _close_stale(frappe.get_doc("App Install Request", name), "Queued", QUEUED_ABANDONED_SECONDS):
			closed.append(name)

	scrubbed = _scrub_orphan_secrets()

	if closed or scrubbed:
		frappe.db.commit()
		frappe.logger("server").info(
			f"reaped {len(closed)} stale install requests; scrubbed {scrubbed} orphaned credentials"
		)
	return {"checked": checked, "closed": closed, "scrubbed": scrubbed}


def _close_stale(request, was: str, limit: int) -> bool:
	try:
		request.db_set(
			{
				"status": "Failed",
				"exit_code": NEVER_RAN,
				"finished_at": frappe.utils.now_datetime(),
				"error_summary": (
					f"Stopped reporting. This was still marked {was} more than "
					f"{limit // 60} minutes after it should have finished, so its worker is "
					"presumed dead. Whether the command itself completed is unknown — check "
					"the bench before re-running."
				),
			},
			update_modified=False,
		)
		if request.is_restore():
			request.clear_restore_secrets()
		frappe.cache.delete_value(CANCEL_KEY.format(name=request.name))
		return True
	except Exception:
		frappe.logger("server").warning(f"could not reap {request.name}", exc_info=True)
		return False


def _scrub_orphan_secrets() -> int:
	"""Clear credentials from requests that have finished.

	`finish()` is meant to be the one place these are cleared, but it is not
	reachable when the process dies inside it — and the last-resort handler that
	runs then could not clear them either. A finished row has no use for a
	database root password under any circumstances, so anything terminal with
	one still attached is scrubbed here.

	THE FIELD LIST COMES FROM THE DOCTYPE, not from a copy kept here. It was a
	copy, naming only the two restore fields, and when provisioning added a
	database root password of its own this would have walked straight past it —
	leaving exactly the credential this function exists to remove.
	"""
	from frappe.utils.password import remove_encrypted_password

	from server.server.doctype.app_install_request.app_install_request import AppInstallRequest

	fields = list(AppInstallRequest.SECRET_FIELDS)
	placeholders = ", ".join(["%s"] * len(fields))

	rows = frappe.db.sql(
		f"""
		SELECT DISTINCT a.name
		FROM `__Auth` a
		JOIN `tabApp Install Request` r ON r.name = a.name
		WHERE a.doctype = 'App Install Request'
		  AND a.fieldname IN ({placeholders})
		  AND r.status IN ('Success', 'Completed With Warnings', 'Failed', 'Cancelled')
		""",
		fields,
		as_dict=True,
	)
	for row in rows:
		for field in fields:
			remove_encrypted_password("App Install Request", row.name, field)
	return len(rows)


def _plan_for(request) -> list:
	"""The steps this request will run through, decided before it starts."""
	if request.is_command():
		command = commands.get(request.bench_command or "")
		return step_plan.for_command(command.label if command else "Run the command")
	if request.is_provision():
		return step_plan.for_provision(
			[repo for _, repo, _ in request.provision_app_list()],
			bool(request.provision_site_name),
			bool(request.provision_domain and request.provision_domain_provider),
		)
	if request.is_console():
		from server.bench import console

		return step_plan.for_console(console.summarise(request.console_command or "", 50))
	if request.is_ssl():
		return step_plan.for_ssl(request.ssl_mode_key(), bool(request.ssl_dry_run))
	if request.is_restore():
		bench_doc = frappe.get_doc("Server Bench", request.bench) if request.bench else None
		return step_plan.for_restore(
			bool(request.restore_backup_first),
			from_remote=request.restore_source == "Remote Server",
			create_site=bool(
				bench_doc and request.install_on_site not in bench_doc.site_names()
			),
			with_domain=bool(request.provision_domain),
		)
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
	#: The previous line and how many times it has repeated since, for
	#: collapsing a redrawn progress bar. Lists rather than plain values
	#: because `emit` is a closure and rebinding would shadow them.
	last_line = [""]
	repeated = [0]
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

	# The namespaced key is computed HERE, on the main thread, and the poller
	# below then does a raw redis GET with it.
	#
	# `frappe.cache.get_value()` cannot be called from the poller thread at all.
	# `frappe.local` is backed by a ContextVar, and a new thread starts with an
	# empty context rather than a copy of its parent's — so `make_key()`, which
	# reads `frappe.local.conf` for the site prefix, raises AttributeError on
	# the very first tick. The bare `except` in the poller swallowed it and the
	# thread returned, so cancellation silently did nothing for the whole life
	# of the job while the interface said "Stopping…".
	#
	# redis-py clients are thread-safe (the connection pool is), so the raw GET
	# is fine; it is only the frappe wrapper around it that is not.
	cancel_key = frappe.cache.make_key(CANCEL_KEY.format(name=name))
	cancel_client = frappe.cache

	def should_cancel() -> bool:
		return cancel_client.get(cancel_key) is not None

	def step(key: str) -> None:
		# Checked at every boundary, not only inside _stream. The poller only
		# runs while a subprocess is running, so a cancel arriving during the
		# pre-flight, between two commands of a restore, or during the closing
		# rescan was simply ignored until the next command started — or never.
		if should_cancel():
			raise InstallAborted("Cancelled.")
		plan.start(key)
		push_steps(force=True)

	#: Lines not yet written to the column. The full log is NOT held in memory
	#: for the life of the job: a cold `bench get-app` with assets emits tens of
	#: thousands of lines and the buffer grew without bound, so a long job
	#: carried its entire log in the worker's RSS as well as rewriting it into
	#: the database over and over.
	pending: list[str] = []
	last_flush = [time.monotonic()]

	def flush() -> None:
		"""Persist buffered output. Also must not raise — see emit()."""
		if not pending:
			return
		try:
			request.append_output("\n".join(pending) + "\n")
			pending.clear()
			last_flush[0] = time.monotonic()
			frappe.db.commit()
		except Exception:
			pending.clear()
			frappe.logger("server").warning(f"could not persist output for {name}", exc_info=True)

	def emit(line: str) -> None:
		"""Record one line of output. MUST NOT raise.

		Every failure path in this job calls emit() on its way out, so an
		exception in here surfaces from inside the handler that was reporting
		the first one — and the job dies with the row still saying Running,
		which no amount of error handling downstream can recover. It happened:
		a stray reference to a variable that had been removed took a backup job
		down and left it spinning in the dock indefinitely.
		"""
		try:
			# Scrubbed before it is stored, streamed or shown. `bench show-config`
			# prints db_password and encryption_key in plain text, so one
			# catalogued read-only command was enough to write both into a log
			# this app renders — undoing the redaction in the config editor.
			line = siteconfig.scrub(line)

			# A progress bar redrawn with carriage returns arrives here as one
			# line per repaint, and `bench new-site` emits the same "40%" forty
			# times in a row. Collapsing consecutive identical lines is what
			# keeps the stored log readable — and this log exists to be copied
			# out and sent to somebody, where thousands of duplicate rows are
			# the difference between a diagnosis and a scroll.
			#
			# Only CONSECUTIVE and only IDENTICAL: a repeated line separated by
			# anything else is a real repetition and is kept.
			if line and line == last_line[0]:
				repeated[0] += 1
				return
			if repeated[0]:
				note = f"    … the line above repeated {repeated[0]} more times"
				repeated[0] = 0
				pending.append(note)
				buffer.append(note)
			last_line[0] = line

			pending.append(line)
			buffer.append(line)
			# The tail is all that is needed after the fact — _tail for the
			# error summary, and the SSL quiet-failure markers, which bench
			# prints at the end. Everything is still in the `output` column.
			if len(buffer) > TAIL_LINES:
				del buffer[: len(buffer) - TAIL_LINES]
			plan.line(line)

			now = time.monotonic()
			if now - last_emit[0] >= STREAM_INTERVAL:
				last_emit[0] = now
				frappe.publish_realtime(
					LOG_EVENT, {"name": name, "line": line}, doctype="App Install Request", docname=name
				)
				push_steps()
			if len(pending) >= PERSIST_EVERY_LINES or (
				pending and time.monotonic() - last_flush[0] >= PERSIST_EVERY_SECONDS
			):
				flush()
		except Exception:
			# Logged, never raised. Losing a log line is a nuisance; losing the
			# job's terminal status is an outage nobody is told about.
			frappe.logger("server").warning(f"could not record output for {name}", exc_info=True)

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

		flush()
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

		# A whole-bench move is a chain of ordinary jobs, and this is the one
		# terminal point every job passes through — so it is where the next
		# action starts. Wrapped, because Invariant 3 applies to everything on
		# the way out of a job: an exception here would surface from inside the
		# handler reporting the failure that just happened.
		try:
			from server.remote import runner

			runner.on_job_finished(name, status)
		except Exception:  # noqa: BLE001
			frappe.logger("server").error(
				f"could not advance the migration after {name}", exc_info=True
			)

		return {"name": name, "status": status, "exit_code": exit_code, "error": error}

	try:
		# Cancelled while it sat in the queue, or already finished. The worker
		# used to write status=Running unconditionally and run it anyway, so a
		# job someone explicitly stopped ran up to two hours later when the
		# single `long` worker got to it.
		if request.is_terminal() or should_cancel():
			frappe.cache.delete_value(CANCEL_KEY.format(name=name))
			if not request.is_terminal():
				request.db_set(
					{
						"status": "Cancelled",
						"exit_code": NEVER_RAN,
						"finished_at": frappe.utils.now_datetime(),
						"error_summary": "Cancelled before the worker picked it up.",
					},
					update_modified=False,
				)
				if request.is_restore():
					request.clear_restore_secrets()
				frappe.db.commit()
			return {"name": name, "status": request.status, "exit_code": NEVER_RAN}

		# A Provision request has no bench yet — it is building one. Everything
		# that would normally come off the bench document comes from settings
		# instead, and the row is linked to the bench once it exists.
		bench_doc = (
			None if request.is_provision() else frappe.get_doc("Server Bench", request.bench)
		)
		lock_name = request.provision_bench_name if request.is_provision() else request.bench
		work_dir = (
			settings.get_bench_root() if request.is_provision() else bench_doc.bench_path
		)
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

		# Put the node this bench's frappe asks for in front of whatever the
		# login shell defaults to. Done once here, so a job that fetches six
		# apps in a row does it once rather than six times — and done again on
		# the next job, because an environment does not outlive the process it
		# was built for. See bench/node.py for why this is not `nvm use`.
		env, node_choice = node.activate(
			env,
			node.required_major(
				None if request.is_provision() else bench_doc.bench_path,
				request.provision_frappe_version if request.is_provision() else None,
			),
		)
		if node_choice.note:
			emit(node_choice.note)

		timeout = settings.get_install_timeout()

		#: Set when the real work succeeded but bench's own post-step did not.
		#: The run still continues — install-app has to happen — and the outcome
		#: is reported as a warning rather than a failure at the end.
		#:
		#: Used by both `get-app` and `bench init`, which fail the same way: the
		#: thing was done, and a trailing `supervisorctl` call that needs root
		#: took the exit code down with it.
		clone_warning = None

		# Scoped to this bench, so two different benches can install in
		# parallel while one bench never sees concurrent get-app calls.
		try:
			with filelock(f"server_bench_install::{lock_name}", timeout=5, is_global=True):
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
				elif request.is_provision():
					from server.bench import provision

					new_bench = request.provision_bench_name
					new_path = os.path.join(work_dir, new_bench)
					version = str(request.provision_frappe_version or "16")
					skip_assets = bool(request.provision_skip_assets)

					def run(argv, cwd, what, budget=None):
						"""One phase. Returns None on success, or a finish()."""
						shown = " ".join(restore.redact(argv))
						request.db_set("command", shown, update_modified=False)
						frappe.db.commit()
						emit(f"$ {shown}")
						code, timed_out = _stream(
							argv, cwd, env, budget or timeout, emit, should_cancel
						)
						if code != 0:
							return finish(
								"Failed",
								exit_code=code,
								error=_explain_failure(code, timed_out, budget or timeout, request, what),
							)
						return None

					step("init")
					interpreter = provision.resolve_interpreter(version)
					emit(f"Using {interpreter}")
					init_argv = provision.build_init_argv(
						settings.bench_executable, new_bench, interpreter, version, skip_assets
					)
					shown = " ".join(init_argv)
					request.db_set("command", shown, update_modified=False)
					frappe.db.commit()
					emit(f"$ {shown}")
					# A cold clone of frappe plus a virtualenv is the longest
					# single thing this app runs.
					init_budget = max(timeout, 3600)
					code, timed_out = _stream(
						init_argv, work_dir, env, init_budget, emit, should_cancel
					)

					if code != 0 and not timed_out and provision.bench_landed(new_path):
						# `bench init` finishes its actual work and THEN runs
						# `sudo supervisorctl status`, which fails on any box
						# without passwordless sudo and takes the exit code
						# with it. The same shape as the `get-app` quirk this
						# app already handles — so ask the disk, not the code.
						clone_warning = (
							"bench init exited non-zero, but the bench is on disk and frappe "
							"imports — almost always its trailing `sudo supervisorctl status`, "
							"which needs root this app does not have. Continuing."
						)
						emit(clone_warning)
						plan.succeed("init", "Built; bench's own exit code was non-zero.")
					elif code != 0:
						return finish(
							"Failed",
							exit_code=code,
							error=_explain_failure(code, timed_out, init_budget, request, "bench init"),
						)

					# From here the bench exists on disk, so everything runs
					# inside it and a failure leaves something to inspect
					# rather than a half-written directory.
					step("ports")
					ports = provision.ports_for(int(request.provision_port_index or 0) or 1)
					emit(
						f"web {ports.webserver}, socketio {ports.socketio}, "
						f"redis {ports.redis_queue}/{ports.redis_cache}"
					)
					for argv, what in (
						(provision.build_port_argv(settings.bench_executable, ports), "setting the ports"),
						(provision.build_redis_argv(settings.bench_executable), "bench setup redis"),
					):
						failure = run(argv, new_path, what, budget=300)
						if failure:
							return failure

					# `bench setup procfile` has no --yes and asks "A Procfile
					# already exists and this will overwrite it. Continue?" —
					# and `bench init` always writes one, so it would prompt
					# every time and abort on closed stdin. Removing it first
					# is what answering the prompt would have done anyway, and
					# it has to be regenerated because the Procfile carries the
					# web port in its own command line.
					stale = os.path.join(new_path, "Procfile")
					try:
						if os.path.exists(stale):
							os.remove(stale)
					except OSError as exc:
						emit(f"Could not remove the old Procfile: {exc}")

					failure = run(
						provision.build_procfile_argv(settings.bench_executable),
						new_path,
						"bench setup procfile",
						budget=300,
					)
					if failure:
						return failure

					apps = request.provision_app_list()
					for profile_name, repo, branch in apps:
						step(f"get:{repo}")
						git_url = _provision_git_url(profile_name, repo)
						get_argv = provision.build_get_app_argv(
							settings.bench_executable, repo, git_url, branch
						)
						shown = " ".join(get_argv)
						request.db_set("command", shown, update_modified=False)
						frappe.db.commit()
						emit(f"$ {shown}")
						get_budget = max(timeout, 3600)
						code, timed_out = _stream(
							get_argv, new_path, env, get_budget, emit, should_cancel
						)

						# `get-app` has the SAME trailing-supervisorctl quirk as
						# `bench init` — it is the reason `_clone_landed` exists
						# for the ordinary install path. Without this, fetching
						# an app during provisioning would fail on any machine
						# without passwordless sudo, having already cloned it.
						if code != 0 and not timed_out and _app_landed(new_path, repo, branch):
							clone_warning = (
								f"{repo} is on disk but bench exited non-zero — usually its "
								"trailing `sudo supervisorctl` call. Continuing."
							)
							emit(clone_warning)
							plan.succeed(f"get:{repo}", "Fetched; bench's own exit code was non-zero.")
						elif code != 0:
							return finish(
								"Failed",
								exit_code=code,
								error=_explain_failure(
									code, timed_out, get_budget, request, f"fetching {repo}"
								),
							)

					site = request.provision_site_name
					if site:
						step("site")
						failure = run(
							provision.build_new_site_argv(
								settings.bench_executable,
								site,
								request.get_password("provision_db_password", raise_exception=False) or "",
								request.get_password("provision_admin_password", raise_exception=False) or "",
							),
							new_path,
							"bench new-site",
						)
						if failure:
							return failure

						for _, repo, _ in apps:
							step(f"install:{repo}")
							failure = run(
								provision.build_install_app_argv(settings.bench_executable, site, repo),
								new_path,
								f"installing {repo}",
							)
							if failure:
								return failure

					if request.provision_domain and request.provision_domain_provider:
						step("domain")
						for line in _provision_domain(request, new_path, site):
							emit(line)

				elif request.is_console():
					from server.bench import console

					step("run")
					argv = console.build_argv(request.console_command)
					# Stored as the operator typed it, not as the three-element
					# argv — `/bin/bash -lc "…"` in the log would be noise around
					# the only part anyone wants to read. Scrubbed on the way in
					# like every other line, in case a secret was typed into it.
					shown = siteconfig.scrub(request.console_command)
					request.db_set("command", shown, update_modified=False)
					frappe.db.commit()
					emit(f"$ {shown}")

					timeout = console.DEFAULT_TIMEOUT
					code, timed_out = _stream(argv, bench_doc.bench_path, env, timeout, emit, should_cancel)
					if code != 0:
						return finish(
							"Failed",
							exit_code=code,
							error=_explain_failure(code, timed_out, timeout, request, "the command"),
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
						# bench stops nginx, gets the certificate, and starts it
						# again. Killed in between — by the watchdog, or by
						# someone pressing Stop — it never reaches the restart,
						# and EVERY site on the machine stays offline with
						# nothing in this app noticing. bench's own error path
						# restarts nginx; being killed skips it.
						_revive_nginx(emit)
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
					#
					# Against the LIVE buffer, not `request.output`. That field is
					# only refreshed every PERSIST_EVERY_LINES lines, and every one
					# of these failures prints a handful of lines and stops — so
					# the field was still the empty string this job set at the
					# start, quiet_failure("") returned None, and the check that
					# exists precisely to catch this caught nothing.
					quiet = ssl.quiet_failure("\n".join(buffer))
					if quiet:
						return finish("Failed", exit_code=code, error=quiet)
				elif request.is_restore():
					if request.restore_source == "Remote Server":
						failure = _pull_from_remote(request, bench_doc, step, emit, finish)
						if failure:
							return failure

					if not _site_exists_on_disk(bench_doc, request.install_on_site):
						failure = _create_site_for_restore(
							request, bench_doc, settings, env, step, emit, finish, should_cancel
						)
						if failure:
							return failure

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

					# Only once the site is actually up. Pointing a name at a
					# site that failed to restore sends real traffic at a
					# half-built one, and the record outlives the mistake.
					if request.provision_domain:
						step("domain")
						for note in _provision_domain(request, bench_doc.bench_path, site):
							emit(note)
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
							# Recorded, then fall through. Returning here skipped
							# `install-app` entirely while telling the operator
							# the app was installed and not to re-run — so the
							# app was on disk and on no site, and the message
							# talked them out of fixing it.
							clone_warning = (
								"Installed successfully. bench's own post-step failed: it runs "
								"`sudo supervisorctl status` to decide whether to restart "
								"processes, and this host has no passwordless sudo. The clone "
								"itself is complete."
							)
						else:
							return finish(
								"Failed",
								exit_code=code,
								error=_explain_failure(
									code, timed_out, timeout, request, "bench get-app"
								),
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

			# A Provision request starts with no bench and ends having made
			# one. Linking it now is what makes the row findable from the
			# bench it created, rather than being the only job in the list
			# with an empty Bench column.
			if request.is_provision() and not request.bench:
				created = request.provision_bench_name
				if frappe.db.exists("Server Bench", created):
					request.db_set("bench", created, update_modified=False)
					emit(f"Linked this request to {created}.")
		except Exception as exc:
			# A stale app list is a cosmetic problem; the operation itself
			# already succeeded. Say so and carry on.
			frappe.logger("server").warning("post-install rescan failed", exc_info=True)
			emit(f"Could not re-read the bench: {exc}")
			plan.fail("rescan", "The operation succeeded; only the refresh failed.")

		if clone_warning:
			return finish("Completed With Warnings", exit_code=0, error=clone_warning)
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
				{
					"status": "Failed",
					"exit_code": NEVER_RAN,
					"finished_at": frappe.utils.now_datetime(),
					"error_summary": f"{type(exc).__name__}: {exc}"[:1000],
				},
				update_modified=False,
			)
			# finish() is documented as the one place credentials cannot escape,
			# and this path runs exactly when finish() failed. Deleting straight
			# from __Auth rather than going through the document, because the
			# document is what just proved unreliable.
			try:
				from frappe.utils.password import remove_encrypted_password

				for field in ("restore_db_password", "restore_encryption_key"):
					remove_encrypted_password("App Install Request", name, field)
			except Exception:
				frappe.logger("server").error(
					f"could not clear restore credentials for {name}", exc_info=True
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

	if what == "bench init":
		return _explain_init_failure(code, request)

	if what == "git pull" and not request.allow_merge:
		return (
			f"{what} exited {code}. The most likely cause is that the branch has diverged from the "
			"remote, which --ff-only refuses rather than merging. Check the log: if a merge is "
			"genuinely what you want, tick 'Allow Merge Commit' and run it again."
		)

	return f"{what} exited {code}."


#: What a failed `bench init` usually means, matched against its own output.
#: Each entry is (substring, explanation). Order matters: the first match wins,
#: so the specific causes come before the general ones.
_INIT_CAUSES = (
	(
		"invalid index-pack output",
		"git ran out of memory unpacking the clone. This is the most common way `bench init` "
		"fails on a machine that is otherwise fine — index-pack is the memory spike, and it is "
		"killed rather than told to slow down. Free some memory and try again; the same clone "
		"usually succeeds on a quieter box.",
	),
	(
		"fetch-pack",
		"the clone did not complete. Either the connection dropped part way, or git ran out of "
		"memory unpacking it — both surface here identically.",
	),
	(
		"Could not resolve host",
		"this machine could not reach github.com. Check DNS and outbound access.",
	),
	(
		"Permission denied (publickey)",
		"git was refused. `bench init` clones frappe over HTTPS, so this is unusual — check "
		"whether a global git insteadOf rule is rewriting the URL to SSH.",
	),
	(
		"No space left on device",
		"the disk filled up during the build.",
	),
)


def _explain_init_failure(code: int, request) -> str:
	"""Why `bench init` failed, and the thing nobody is told otherwise.

	TWO PROBLEMS THIS SOLVES, both seen on the first real run.

	The cause is buried. bench prints a Python traceback wrapping a
	`CommandFailedError`, and the line that says what actually went wrong —
	`fatal: fetch-pack: invalid index-pack output` — is a hundred lines above
	it. "bench init exited 1" is true and useless.

	The directory is left behind. On failure bench asks "Do you want to
	rollback these changes? [y/N]" and a job has no stdin, so it aborts and
	the half-built directory stays. The next attempt then fails the pre-flight
	with "already exists", which reads as a different problem entirely. Saying
	so here is the difference between one confusing failure and two.
	"""
	from server.bench import provision  # noqa: F401  (kept for symmetry/imports)

	tail = "\n".join((request.output or "").strip().splitlines()[-80:])
	cause = ""
	for needle, explanation in _INIT_CAUSES:
		if needle in tail:
			cause = explanation
			break

	leftover = (
		f"The partly-built directory has been left in place — bench asks whether to roll back and "
		f"a job has no way to answer, so it aborts. Remove it before trying again: "
		f"rm -rf <bench root>/{request.provision_bench_name}"
	)

	if cause:
		return f"bench init exited {code}: {cause} {leftover}"
	return (
		f"bench init exited {code}. The reason is in the log above, usually a hundred lines up "
		f"from the traceback. {leftover}"
	)


def _tail(lines: list[str], count: int = 12) -> str:
	return "\n".join(lines[-count:])


def _worst_case_seconds(request, settings) -> int:
	"""The most time this particular request is allowed to spend.

	The RQ death penalty has to be larger than the in-process watchdog, or RQ
	kills the job first and the operator gets `JobTimeoutException` instead of
	the actionable "raise Install Timeout and try again" message this file goes
	to some trouble to produce. Three shapes legitimately exceed one budget:

	  * a catalogue command carries its own timeout (`bench update` is 7200s,
	    against a 3600s default);
	  * a restore with the safety backup runs two commands, each budgeted in
	    full;
	  * a clone followed by install-app, likewise.
	"""
	budget = settings.get_install_timeout()

	if request.is_command():
		command = commands.get(request.bench_command or "")
		return command.timeout if command else budget
	if request.is_provision():
		# A clone of frappe, a virtualenv, one clone per app, a site, and an
		# install per app. Budgeted generously because the failure mode of
		# guessing low is RQ killing the job with its own opaque error instead
		# of this file's actionable one.
		apps = max(1, len(request.provision_app_list()))
		return max(budget, 3600) * (2 + apps)
	if request.is_console():
		from server.bench import console

		return console.DEFAULT_TIMEOUT
	if request.is_ssl():
		return ssl.SSL_TIMEOUT
	if request.is_restore():
		return budget * 2 if request.restore_backup_first else budget
	if request.is_pull():
		return budget
	# Clone, plus install-app when a site was named.
	return budget * 2 if request.install_on_site else budget


def enqueue_install_request(name: str) -> str:
	"""Queue a request. Returns the job id."""
	job_id = f"server::app_install::{name}"
	request = frappe.get_doc("App Install Request", name)

	frappe.enqueue(
		"server.bench.installer.run_install_request",
		queue="long",
		# Derived from what this job may actually spend, not from one fixed
		# budget. The queue's own 1500s default is not enough for a cold clone
		# plus a pip install of a large app either.
		timeout=_worst_case_seconds(request, get_settings()) + 180,
		job_id=job_id,
		deduplicate=True,
		enqueue_after_commit=True,
		name=name,
	)
	return job_id
