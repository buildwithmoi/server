# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""A minimal GitHub REST client, for listing repositories and branches.

WHY A TOKEN IS NEEDED HERE WHEN CLONING DOES NOT. An SSH key authenticates the
git transport; it cannot query GitHub's HTTP API at all. So listing a private
organisation's repositories requires a personal access token, while cloning them
continues to use the key. The token is therefore read-only in practice and is
never handed to git — it is used for exactly two endpoints, both GETs.

WHY NOT `requests`. urllib is in the standard library, this needs two GETs with
pagination, and adding an HTTP library to a bench's dependency list to save
twenty lines is not a trade worth making.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://api.github.com"
PER_PAGE = 100
TIMEOUT = 30

#: GitHub caps this at 100 per page; ten pages is a thousand repositories, far
#: beyond any organisation this is aimed at, and it stops a pathological account
#: turning one click into a minute of paging.
MAX_PAGES = 10


class GitHubError(Exception):
	"""Anything that stopped us reading from the API, phrased for a human."""


def _request(
	path: str, token: str | None = None, params: dict | None = None, subject: str = "account"
) -> tuple[list | dict, dict]:
	url = f"{API_ROOT}{path}"
	if params:
		url = f"{url}?{urllib.parse.urlencode(params)}"

	headers = {
		"Accept": "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
		"User-Agent": "frappe-server-app",
	}
	if token:
		headers["Authorization"] = f"Bearer {token}"

	request = urllib.request.Request(url, headers=headers, method="GET")
	try:
		with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
			return json.loads(response.read().decode("utf-8")), dict(response.headers)
	except urllib.error.HTTPError as exc:
		raise GitHubError(_explain_http(exc, bool(token), subject)) from exc
	except (urllib.error.URLError, TimeoutError, OSError) as exc:
		raise GitHubError(f"Could not reach api.github.com: {exc}") from exc
	except ValueError as exc:
		raise GitHubError(f"GitHub returned something that is not JSON: {exc}") from exc


def _explain_http(exc: urllib.error.HTTPError, had_token: bool, subject: str = "account") -> str:
	"""Turn a status code into the thing the operator actually needs to change.

	`subject` matters. A 404 from the repository-list endpoint means the ACCOUNT
	is wrong; a 404 from the branch endpoint means the REPOSITORY is. Reporting
	the account phrasing for a branch lookup sends someone off checking a
	setting that was right all along — which is exactly what happened the first
	time this was exercised.
	"""
	if exc.code == 401:
		return "GitHub rejected the access token. It may be expired, revoked, or mistyped."
	if exc.code == 403:
		remaining = exc.headers.get("X-RateLimit-Remaining")
		if remaining == "0":
			return (
				"GitHub rate limit reached. Unauthenticated requests are limited to 60 per hour — "
				"adding an access token raises it to 5000."
				if not had_token
				else "GitHub rate limit reached for this token. It resets within the hour."
			)
		return "GitHub refused the request. The token may lack the 'repo' scope, or SSO is not authorised for it."
	if exc.code == 404:
		if subject == "repository":
			return (
				"No such repository on that account, or it is private and this token cannot see it."
				if had_token
				else "No such repository on that account, or it is private. Add an access token with "
				"the 'repo' scope to reach private repositories."
			)
		return (
			"No such account, or it has no repositories visible to this token. Check the account "
			"name and whether it is an organisation or a user — they are different API endpoints."
			if had_token
			else "No such account, or its repositories are private. A token with the 'repo' scope is "
			"needed to see private repositories."
		)
	return f"GitHub returned HTTP {exc.code}."


def list_repos(account: str, account_type: str = "Organisation", token: str | None = None) -> list[dict]:
	"""Every repository on an account, newest push first.

	Organisations and users are genuinely different endpoints; using the wrong
	one returns 404 rather than an empty list, which is why the profile records
	which it is instead of guessing.
	"""
	account = (account or "").strip().strip("/")
	if not account:
		raise GitHubError("No GitHub account configured on this profile.")

	segment = "orgs" if account_type == "Organisation" else "users"
	collected: list[dict] = []

	for page in range(1, MAX_PAGES + 1):
		payload, _ = _request(
			f"/{segment}/{urllib.parse.quote(account)}/repos",
			token=token,
			params={"per_page": PER_PAGE, "page": page, "sort": "pushed", "type": "all"},
			subject="account",
		)
		if not isinstance(payload, list):
			raise GitHubError("GitHub returned an unexpected shape for the repository list.")
		collected.extend(payload)
		if len(payload) < PER_PAGE:
			break

	return [
		{
			"repo_name": repo.get("name"),
			"default_branch": repo.get("default_branch"),
			"is_private": 1 if repo.get("private") else 0,
			"is_archived": 1 if repo.get("archived") else 0,
			"description": (repo.get("description") or "")[:500],
			"pushed_at": _to_naive(repo.get("pushed_at")),
			"ssh_url": repo.get("ssh_url"),
		}
		for repo in collected
		if repo.get("name")
	]


def list_branches(account: str, repo: str, token: str | None = None) -> tuple[list[dict], bool]:
	"""Branch names for one repository. Returns (branches, truncated).

	Some repositories carry hundreds of branches — erpnext has over six hundred,
	which is seven pages and several seconds. The caller is told when the list
	hit the page cap so it can say so rather than quietly showing a subset.
	"""
	account = (account or "").strip().strip("/")
	repo = (repo or "").strip().removesuffix(".git")
	if not account or not repo:
		raise GitHubError("Both an account and a repository are required.")

	collected: list[dict] = []
	truncated = False
	for page in range(1, MAX_PAGES + 1):
		payload, _ = _request(
			f"/repos/{urllib.parse.quote(account)}/{urllib.parse.quote(repo)}/branches",
			token=token,
			params={"per_page": PER_PAGE, "page": page},
			subject="repository",
		)
		if not isinstance(payload, list):
			raise GitHubError("GitHub returned an unexpected shape for the branch list.")
		collected.extend(payload)
		if len(payload) < PER_PAGE:
			break
		if page == MAX_PAGES:
			# Silently returning a partial list would make a branch that exists
			# look like it does not. Say so instead.
			truncated = True

	branches = [
		{"name": branch.get("name"), "protected": bool(branch.get("protected"))}
		for branch in collected
		if branch.get("name")
	]
	return branches, truncated


def _to_naive(timestamp: str | None) -> str | None:
	"""GitHub sends `2026-08-24T13:32:02Z`; MariaDB DATETIME will not take the Z.

	The same class of bug the SSH ingest hit — a timezone-aware value that the
	column rejects outright — so it is stripped at the boundary here too.
	"""
	if not timestamp:
		return None
	return timestamp.replace("T", " ").replace("Z", "").split(".")[0]
