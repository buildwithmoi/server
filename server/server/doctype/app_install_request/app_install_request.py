# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A request to clone an app into a bench, and the record of what happened."""

import os
import re

import frappe
from frappe.model.document import Document

from server.bench import doctor

#: Repository names are used verbatim as a directory name and as a python module
#: name, so anything outside this set is rejected rather than escaped.
VALID_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
VALID_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
VALID_SITE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")

#: Remotes we are willing to clone from. With shell=False and a list argv there
#: is no injection to worry about, but this keeps typos and pasted nonsense from
#: becoming a three-minute subprocess failure.
VALID_REMOTE = re.compile(r"^(?:git@[\w.-]+:|ssh://[\w.@-]+/|https://[\w.-]+/)")

TERMINAL_STATUSES = ("Success", "Failed", "Cancelled")


class AppInstallRequest(Document):
	def validate(self):
		self._validate_inputs()
		self.resolved_git_url = self.resolve_git_url()
		self.app_name = self.derive_app_name()

	def _validate_inputs(self):
		if self.branch and not VALID_BRANCH.match(self.branch):
			frappe.throw(f"{self.branch!r} is not a valid branch name.")
		if self.install_on_site and not VALID_SITE.match(self.install_on_site):
			frappe.throw(f"{self.install_on_site!r} is not a valid site name.")

		if self.source_type == "Git URL":
			if not self.git_url:
				frappe.throw("Enter a Git URL, or switch the source to Org + Repo.")
			if not VALID_REMOTE.match(self.git_url.strip()):
				frappe.throw(
					"Git URL must start with git@host:, ssh://, or https://.",
					title="Unsupported Remote",
				)
		else:
			if not self.repo:
				frappe.throw("Enter the repository name.")
			if not VALID_REPO.match(self.repo.strip()):
				frappe.throw(
					f"{self.repo!r} is not a valid repository name. Use just the name, e.g. gh_erp — "
					"not the full URL.",
					title="Invalid Repository",
				)

	def resolve_git_url(self) -> str:
		"""Build the remote to clone from.

		The organisation maps to an ~/.ssh/config Host alias so the right key is
		offered — but ONLY if that alias actually exists. Emitting
		`git@github-carbonite:...` on a machine with no such Host block produces
		"Could not resolve hostname", which is a far more confusing failure than
		the ambiguous-identity problem the alias was meant to solve. So the
		alias is an upgrade when present and plain github.com otherwise, and
		`bench/doctor.py` is what tells you the alias is missing.
		"""
		if self.source_type == "Git URL":
			return (self.git_url or "").strip()

		org = (self.github_org or "").strip()
		repo = (self.repo or "").strip().removesuffix(".git")
		alias = doctor.ORG_ALIASES.get(org)
		configured = alias in (doctor.read_ssh_config().get("hosts") or [])
		host = alias if (alias and configured) else "github.com"
		return f"git@{host}:{org}/{repo}.git"

	def derive_app_name(self) -> str:
		"""The frappe app name, which is the repo name without decoration.

		Passed to `bench get-app` explicitly. bench can infer it, but it infers
		from the URL — and when the URL carries a Host alias the inference is
		wrong, producing an app directory named after the alias.
		"""
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

	def is_terminal(self) -> bool:
		return self.status in TERMINAL_STATUSES

	def append_output(self, chunk: str) -> None:
		"""Persist log output without touching `modified`.

		`db_set` with update_modified=False on purpose: the log is appended many
		times during a run, and bumping the timestamp on each flush would make
		the document look edited by a human and would fight any concurrent read.
		"""
		self.db_set("output", chunk, update_modified=False)
