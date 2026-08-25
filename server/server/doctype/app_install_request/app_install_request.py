# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A request to bring an app into a bench, or to bring one up to date.

Two operations share this record because they share everything around the
command — the bench, the queueing, the lock, the streamed log, the exit code —
and differ only in the argv and the pre-flights. Splitting them into two
doctypes would duplicate all of that to avoid one `if`.
"""

import os
import re

import frappe
from frappe.model.document import Document

#: Repository names become a directory name and a python module name, so
#: anything outside this set is refused rather than escaped.
VALID_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
VALID_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
VALID_SITE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")

#: Remotes we will clone from. `shell=False` with a list argv already makes
#: injection impossible; this keeps typos and pasted nonsense from becoming a
#: three-minute subprocess failure.
VALID_REMOTE = re.compile(r"^(?:git@[\w.-]+:|ssh://[\w.@-]+/|https://[\w.-]+/)")

TERMINAL_STATUSES = ("Success", "Completed With Warnings", "Failed", "Cancelled")

#: Statuses that mean the work was actually done.
OK_STATUSES = ("Success", "Completed With Warnings")

OP_CLONE = "Clone"
OP_PULL = "Pull"
OP_COMMAND = "Command"
OP_SSL = "SSL"
OP_RESTORE = "Restore"

#: Form labels for the two SSL operations, mapped to the modes `bench.ssl` uses.
SSL_MODES = {"Issue Or Reinstall": "issue", "Renew": "renew"}


class AppInstallRequest(Document):
	def validate(self):
		self.operation = self.operation or OP_CLONE
		self._validate_common()
		if self.operation == OP_COMMAND:
			self._validate_command()
		elif self.operation == OP_SSL:
			self._validate_ssl()
		elif self.operation == OP_RESTORE:
			self._validate_restore()
		elif self.operation == OP_PULL:
			self._validate_pull()
		else:
			self._validate_clone()

	# ------------------------------------------------------------------

	def _validate_common(self):
		if self.branch and not VALID_BRANCH.match(self.branch):
			frappe.throw(f"{self.branch!r} is not a valid branch name.")
		if self.install_on_site and not VALID_SITE.match(self.install_on_site):
			frappe.throw(f"{self.install_on_site!r} is not a valid site name.")

	def _validate_command(self):
		"""A command must exist in the catalogue and be one we will run.

		Validated here as well as in the API because the record can be created
		by either path, and a request that cannot run should never reach the
		queue in the first place.
		"""
		import json

		from server.bench import commands

		command = commands.get(self.bench_command or "")
		if not command:
			frappe.throw(f"{self.bench_command!r} is not a known bench command.", title="Unknown Command")
		if not command.runnable:
			frappe.throw(
				command.unsupported_reason or f"{command.label} cannot be run from here.",
				title="Not Runnable",
			)
		if command.scope == commands.SCOPE_SITE and not self.install_on_site:
			frappe.throw(f"{command.label} needs a site.")

		# Build it now purely to surface a bad parameter at save time rather
		# than three seconds into a worker.
		params = json.loads(self.command_params or "{}")
		try:
			commands.build_argv(command, "/usr/local/bin/bench", self.install_on_site, params)
		except commands.CommandRefused as exc:
			frappe.throw(str(exc), title="Cannot Build Command")

		self.app_name = command.label

	def _validate_ssl(self):
		"""An SSL request must name an operation, and a site if it issues.

		Built here as well as in the worker so a domain that certbot would
		reject is refused at save time rather than after nginx has been stopped.
		"""
		from server.bench import ssl

		mode = SSL_MODES.get(self.ssl_mode or "")
		if not mode:
			frappe.throw("Choose whether to issue a certificate or renew the existing ones.")

		if mode == ssl.MODE_ISSUE:
			site = (self.install_on_site or "").strip()
			if not site:
				frappe.throw("Issuing a certificate needs a site.")
			bench = frappe.get_doc("Server Bench", self.bench)
			if site not in bench.site_names():
				frappe.throw(
					f"{site!r} is not a site on {self.bench}. "
					f"Known sites: {', '.join(bench.site_names()) or 'none'}."
				)

		try:
			ssl.build_argv(mode, "/usr/local/bin/bench", self.install_on_site, self.ssl_domain, self.ssl_dry_run)
		except ssl.SSLRefused as exc:
			# certbot missing is a server condition, not a bad request — it must
			# not block saving a record that will run on a box that has it.
			if "not installed" not in str(exc):
				frappe.throw(str(exc), title="Cannot Build Command")

		self.app_name = f"SSL · {self.ssl_mode}"

	def _validate_restore(self):
		"""A restore must name a site that exists and a backup still on disk."""
		from server.bench import restore

		site = (self.install_on_site or "").strip()
		if not site:
			frappe.throw("Restoring needs a site.")

		bench = frappe.get_doc("Server Bench", self.bench)
		if site not in bench.site_names():
			frappe.throw(
				f"{site!r} is not a site on {self.bench}. "
				f"Known sites: {', '.join(bench.site_names()) or 'none'}."
			)

		# Resolved now so a rotated-away backup, or a path that points outside
		# the bench, is refused before the record exists rather than after the
		# queue has picked it up.
		try:
			backup = self.resolve_backup(bench.bench_path)
		except restore.RestoreRefused as exc:
			frappe.throw(str(exc), title="Cannot Restore")

		if backup.encrypted and not self.get_password("restore_encryption_key", raise_exception=False):
			frappe.throw(
				"That backup is encrypted. Restoring it needs the encryption key from the site it "
				"was taken from.",
				title="Encryption Key Required",
			)

		self.app_name = f"Restore · {site}"

	def _validate_pull(self):
		if not self.app_name:
			frappe.throw("Choose which app to pull.")
		if not VALID_REPO.match(self.app_name.strip()):
			frappe.throw(f"{self.app_name!r} is not a valid app name.")

		bench = frappe.get_doc("Server Bench", self.bench)
		if not bench.has_app(self.app_name):
			frappe.throw(
				f"{self.bench} has no app called {self.app_name!r}. Pull updates an app that is "
				"already there — use Clone to bring in a new one.",
				title="App Not In Bench",
			)

		# A pull is the only operation here that has no remote of its own; it
		# uses whatever the checkout already points at.
		self.resolved_git_url = next(
			(row.git_url for row in bench.apps if row.app_name == self.app_name), None
		)

	def _validate_clone(self):
		if self.source_type == "Git URL":
			if not self.git_url:
				frappe.throw("Enter a Git URL, or switch the source to a GitHub Profile.")
			if not VALID_REMOTE.match(self.git_url.strip()):
				frappe.throw(
					"Git URL must start with git@host:, ssh://, or https://.", title="Unsupported Remote"
				)
		else:
			if not self.github_profile:
				frappe.throw("Choose a GitHub profile, or switch the source to Git URL.")
			if not self.repo:
				frappe.throw("Choose a repository.")
			if not VALID_REPO.match(self.repo.strip()):
				frappe.throw(
					f"{self.repo!r} is not a valid repository name. Use just the name, e.g. gh_erp — "
					"not the full URL.",
					title="Invalid Repository",
				)

		self.resolved_git_url = self.resolve_git_url()
		self.app_name = self.derive_app_name()

	# ------------------------------------------------------------------

	def resolve_git_url(self) -> str:
		"""Build the remote to clone from.

		A profile can name an ~/.ssh/config Host alias so the right key is
		offered. The alias is used only when it actually exists — emitting
		`git@github-carbonite:...` on a machine with no such Host block gives
		"Could not resolve hostname", a worse failure than the ambiguous
		identity the alias was meant to fix.
		"""
		if self.source_type == "Git URL":
			return (self.git_url or "").strip()

		profile = frappe.get_doc("GitHub Profile", self.github_profile)
		alias = (profile.ssh_host_alias or "").strip()
		if alias:
			from server.bench import doctor

			if alias not in (doctor.read_ssh_config().get("hosts") or []):
				alias = ""
		host = alias or "github.com"
		repo = (self.repo or "").strip().removesuffix(".git")
		return f"git@{host}:{profile.account}/{repo}.git"

	def derive_app_name(self) -> str:
		if self.source_type != "Git URL":
			return (self.repo or "").strip().removesuffix(".git")

		tail = (self.git_url or "").strip().rstrip("/").rsplit("/", 1)[-1]
		if ":" in tail and "/" not in tail:
			tail = tail.rsplit(":", 1)[-1]
		return tail.removesuffix(".git")

	# ------------------------------------------------------------------

	@property
	def app_path(self) -> str:
		bench_path = frappe.db.get_value("Server Bench", self.bench, "bench_path") or ""
		return os.path.join(bench_path, "apps", self.app_name or "")

	def is_pull(self) -> bool:
		return self.operation == OP_PULL

	def is_command(self) -> bool:
		return self.operation == OP_COMMAND

	def is_ssl(self) -> bool:
		return self.operation == OP_SSL

	def is_restore(self) -> bool:
		return self.operation == OP_RESTORE

	def resolve_backup(self, bench_path: str):
		"""The backup this request restores, however it was chosen.

		Both sources converge on one BackupSet so the argv builder, the
		pre-flights and the job body have a single shape to work with — a
		second code path for hand-picked files is a second thing to get wrong.
		"""
		from server.bench import restore

		if self.restore_source == "Chosen Files":
			return restore.resolve_chosen(
				bench_path,
				self.install_on_site,
				self.restore_database_file,
				self.restore_public_file,
				self.restore_private_file,
			)
		if not self.restore_backup_key:
			raise restore.RestoreRefused("Choose which backup to restore.")
		return restore.find(bench_path, self.install_on_site, self.restore_backup_key)

	def clear_restore_secrets(self) -> None:
		"""Drop the credentials once the job is over.

		They are only ever needed for the length of one subprocess. Keeping a
		database root password after that is a standing risk for no benefit,
		and this app exists because a server was broken into.

		The delete has to hit `__Auth`, not the column. A Password field stores
		the encrypted value in `__Auth` and leaves a `*****` placeholder in the
		doctype's own column, so clearing the column removes the mask and leaves
		the secret exactly where it was — which is what an earlier version of
		this method did, and it looked like it was working.
		"""
		from frappe.utils.password import remove_encrypted_password

		for field in ("restore_db_password", "restore_encryption_key"):
			remove_encrypted_password(self.doctype, self.name, field)
			if self.get(field):
				self.db_set(field, None, update_modified=False)

	def ssl_mode_key(self) -> str:
		return SSL_MODES.get(self.ssl_mode or "", "")

	def is_terminal(self) -> bool:
		return self.status in TERMINAL_STATUSES

	def succeeded(self) -> bool:
		return self.status in OK_STATUSES

	def append_output(self, chunk: str) -> None:
		"""Append to the stored log without touching `modified`.

		A genuine append, via SQL CONCAT. It used to take the whole accumulated
		log and rewrite the column with it, which made persistence quadratic:
		a `bench get-app` with assets emits tens of thousands of lines — git
		progress is split on bare carriage returns, so every redraw of
		"Receiving objects: N%" is its own line — and at 50k lines the job spent
		more time rewriting a 4 MB longtext than running the command.

		`modified` is deliberately left alone: bumping it on every flush would
		make the document look hand-edited, and the reaper measures staleness
		from `started_at` precisely because this field never moves.
		"""
		if not chunk:
			return
		frappe.db.sql(
			"""UPDATE `tabApp Install Request`
			   SET output = CONCAT(COALESCE(output, ''), %(chunk)s)
			   WHERE name = %(name)s""",
			{"chunk": chunk, "name": self.name},
		)
		# Deliberately NOT mirrored onto self.output. Accumulating it here put
		# the entire log back in the worker's memory — which is exactly what
		# capping the caller's buffer was meant to stop — and made each append
		# an O(n) string copy on top. Anything that needs the full log reads the
		# column.
		self.output = None
