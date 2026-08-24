# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A GitHub account whose repositories can be installed from.

WHY A TOKEN LIVES HERE WHEN CLONING USES A KEY. An SSH key authenticates git,
not GitHub's HTTP API — there is no way to list a private organisation's
repositories with a key. So the token exists purely to read two endpoints, and
it is never handed to git: clones continue to go over SSH. Keeping the two
credentials separate means a leaked token cannot push, and a compromised key
cannot enumerate the organisation.
"""

import frappe
from frappe.model.document import Document

from server.bench import github


class GitHubProfile(Document):
	def validate(self):
		self.account = (self.account or "").strip().strip("/")
		if not self.account:
			frappe.throw("Enter the GitHub organisation or username.")
		if "/" in self.account or "@" in self.account:
			frappe.throw(
				f"{self.account!r} does not look like a GitHub account. Use just the organisation "
				"or username as it appears in a repository URL — not a URL or an email address.",
				title="Invalid Account",
			)
		self._enforce_single_default()

	def _enforce_single_default(self):
		"""Only one profile can be the default; the newest choice wins.

		Silently demoting the previous default is kinder than refusing the save
		and making someone go and clear the other one first.
		"""
		if not self.is_default:
			return
		others = frappe.get_all(
			"GitHub Profile", filters={"is_default": 1, "name": ("!=", self.name or "")}, pluck="name"
		)
		for other in others:
			frappe.db.set_value("GitHub Profile", other, "is_default", 0, update_modified=False)

	def get_token(self) -> str | None:
		return self.get_password("access_token", raise_exception=False)

	def clone_host(self) -> str:
		"""The SSH host to clone through — an alias if one is configured."""
		return (self.ssh_host_alias or "").strip() or "github.com"

	def git_url(self, repo: str) -> str:
		return f"git@{self.clone_host()}:{self.account}/{repo.strip().removesuffix('.git')}.git"

	# ------------------------------------------------------------------

	def sync_repos(self) -> dict:
		"""Refresh the cached repository list from GitHub.

		Cached rather than fetched per keystroke so the install dialog can filter
		instantly. Repositories are created rarely; a stale list costs one
		re-sync, whereas a live call on every search would put a network round
		trip between typing and seeing anything.
		"""
		try:
			repos = github.list_repos(self.account, self.account_type, self.get_token())
		except github.GitHubError as exc:
			self.db_set(
				{"sync_error": str(exc)[:1000], "last_synced_at": frappe.utils.now_datetime()},
				update_modified=False,
			)
			frappe.db.commit()
			return {"ok": False, "error": str(exc), "count": self.repo_count or 0}

		self.set("repos", [])
		for repo in repos:
			self.append("repos", repo)
		self.repo_count = len(repos)
		self.last_synced_at = frappe.utils.now_datetime()
		self.sync_error = None
		self.flags.ignore_permissions = True
		self.save()
		frappe.db.commit()
		return {"ok": True, "count": len(repos), "private": sum(r["is_private"] for r in repos)}

	def branches(self, repo: str) -> tuple[list[dict], bool]:
		"""Live branch list for one repository.

		NOT cached, unlike repositories: branches are created and deleted
		constantly, and picking a branch that no longer exists fails three
		minutes into a clone rather than immediately.
		"""
		return github.list_branches(self.account, repo, self.get_token())


def get_default_profile() -> str | None:
	names = frappe.get_all("GitHub Profile", filters={"is_default": 1}, pluck="name", limit=1)
	if names:
		return names[0]
	names = frappe.get_all("GitHub Profile", pluck="name", order_by="profile_name asc", limit=1)
	return names[0] if names else None
