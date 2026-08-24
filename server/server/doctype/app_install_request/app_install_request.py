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

TERMINAL_STATUSES = ("Success", "Failed", "Cancelled")

OP_CLONE = "Clone"
OP_PULL = "Pull"


class AppInstallRequest(Document):
	def validate(self):
		self.operation = self.operation or OP_CLONE
		self._validate_common()
		if self.operation == OP_PULL:
			self._validate_pull()
		else:
			self._validate_clone()

	# ------------------------------------------------------------------

	def _validate_common(self):
		if self.branch and not VALID_BRANCH.match(self.branch):
			frappe.throw(f"{self.branch!r} is not a valid branch name.")

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
		if self.install_on_site and not VALID_SITE.match(self.install_on_site):
			frappe.throw(f"{self.install_on_site!r} is not a valid site name.")

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

	def is_terminal(self) -> bool:
		return self.status in TERMINAL_STATUSES

	def append_output(self, chunk: str) -> None:
		"""Persist log output without touching `modified`.

		The log is appended many times during a run; bumping the timestamp on
		every flush would make the document look hand-edited and fight any
		concurrent read.
		"""
		self.db_set("output", chunk, update_modified=False)
