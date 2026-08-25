# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Read-only diagnostics for git/SSH access to private repositories.

WHY THIS EXISTS AS A SEPARATE STEP. A `bench get-app` against a private repo
that cannot authenticate fails several minutes in, from inside a CLI, with a
message about the repository not existing. That is the same message GitHub
returns for "the repo is there but this key cannot see it", which is the case
you are actually in nine times out of ten. Checking first turns a confusing
five-minute failure into an immediate, accurate one.

WHY IT NEVER WRITES. Everything here reads: it will tell you exactly what to put
in ~/.ssh/config and refuse to put it there itself. A web application silently
rewriting a user's SSH configuration is an unauditable side effect on the single
most security-sensitive file in their home directory, and the app runs as the
bench user precisely so it does not need that kind of reach.
"""

from __future__ import annotations

import os
import re
import subprocess

import frappe

from server.server.doctype.server_settings.server_settings import get_settings

#: Remotes this app will contact, and branch names it will pass to git.
#:
#: Deliberately duplicated from App Install Request rather than imported: the
#: doctype's copy is enforced in `validate`, which only runs when a document is
#: saved, and the probe endpoint never saves one. A shared constant that is
#: only checked on one of two paths is worse than two constants that are both
#: checked, so these live next to the code that shells out.
VALID_REMOTE = re.compile(r"^(?:git@[\w.-]+:|ssh://[\w.@-]+/|https://[\w.-]+/)[\w./~@-]{1,300}$")

#: Must begin alphanumeric, so a branch can never be read as an option.
VALID_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")

SSH_DIR = os.path.expanduser("~/.ssh")
SSH_CONFIG = os.path.join(SSH_DIR, "config")
TIMEOUT = 25

#: The two GitHub identities in play, and the alias each should use. Aliases
#: matter because ssh offers every key it can find until one is accepted, and
#: GitHub authenticates you as whoever owns the first accepted key — which is
#: how you get "Repository not found" on a repo you demonstrably have access to.
ORG_ALIASES = {
	"Carbonite-Solutions-Ltd": "github-carbonite",
	"buildwithmoi": "github-buildwithmoi",
}

_GITHUB_GREETING = re.compile(r"Hi (?P<user>[^!]+)!")


def _run(argv: list[str], timeout: int = TIMEOUT) -> tuple[int, str, str]:
	try:
		result = subprocess.run(
			argv,
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=timeout,
			check=False,
			env=get_settings().get_bench_env(),
		)
	except subprocess.TimeoutExpired:
		return 124, "", f"timed out after {timeout}s"
	except OSError as exc:
		return 127, "", str(exc)
	return result.returncode, result.stdout.strip(), result.stderr.strip()


def list_keys() -> list[dict]:
	"""Private keys in ~/.ssh, and whether each is usable non-interactively.

	The passphrase check is the important one. There is no ssh-agent running
	under a background worker, so a key with a passphrase can never be used by
	an automated clone — it would sit waiting for input nobody can type, which
	is why BatchMode=yes is forced everywhere else in this app.
	"""
	keys = []
	try:
		entries = sorted(os.scandir(SSH_DIR), key=lambda e: e.name)
	except OSError:
		return keys

	for entry in entries:
		if not entry.is_file() or entry.name.endswith(".pub"):
			continue
		if entry.name in ("config", "known_hosts", "known_hosts.old", "authorized_keys"):
			continue

		public = f"{entry.path}.pub"
		if not os.path.exists(public):
			continue

		mode = oct(os.stat(entry.path).st_mode & 0o777)
		code, _, _ = _run(["ssh-keygen", "-y", "-f", entry.path], timeout=10)
		comment = ""
		try:
			with open(public, encoding="utf-8") as fh:
				parts = fh.read().strip().split(" ", 2)
				comment = parts[2] if len(parts) > 2 else ""
		except OSError:
			pass

		keys.append(
			{
				"name": entry.name,
				"path": entry.path,
				"permissions": mode,
				"permissions_ok": mode == "0o600",
				"comment": comment,
				"passphrase_free": code == 0,
			}
		)
	return keys


def read_ssh_config() -> dict:
	"""What Host blocks exist, and do the expected aliases resolve?"""
	exists = os.path.exists(SSH_CONFIG)
	hosts: list[str] = []
	if exists:
		try:
			with open(SSH_CONFIG, encoding="utf-8") as fh:
				for line in fh:
					if line.strip().lower().startswith("host "):
						hosts.extend(line.split(None, 1)[1].split())
		except OSError:
			pass

	mode = oct(os.stat(SSH_CONFIG).st_mode & 0o777) if exists else None
	return {
		"exists": exists,
		"path": SSH_CONFIG,
		"permissions": mode,
		"permissions_ok": mode in (None, "0o600"),
		"hosts": hosts,
		"missing_aliases": [alias for alias in ORG_ALIASES.values() if alias not in hosts],
	}


def probe_host(host: str) -> dict:
	"""Ask GitHub who we authenticate as through `host`, without cloning.

	`ssh -T git@github.com` exits 1 on success — GitHub greets you and then
	closes the connection because it offers no shell. So the greeting, not the
	exit code, is the signal.
	"""
	code, resolved, _ = _run(["ssh", "-G", host], timeout=10)
	identity_files = []
	real_host = host
	if code == 0:
		for line in resolved.splitlines():
			if line.startswith("identityfile "):
				identity_files.append(os.path.expanduser(line.split(None, 1)[1]))
			elif line.startswith("hostname "):
				real_host = line.split(None, 1)[1]

	code, out, err = _run(["ssh", "-o", "BatchMode=yes", "-T", f"git@{host}"])
	greeting = f"{out}\n{err}".strip()
	match = _GITHUB_GREETING.search(greeting)

	return {
		"host": host,
		"hostname": real_host,
		"identity_files": [p for p in identity_files if os.path.exists(p)],
		"authenticated_as": match.group("user").strip() if match else None,
		"message": greeting.splitlines()[0] if greeting else "",
	}


class RepoRefused(Exception):
	"""Raised when a remote or branch will not be probed."""


def check_repo(git_url: str, branch: str | None = None) -> dict:
	"""Can we reach this repo, and does the branch exist?

	`git ls-remote` is the single highest-value preflight in the app: it proves
	the key is authorised and the branch is real in about a second, instead of
	discovering either problem three minutes into a clone.

	VALIDATED HERE, not only at the caller. `shell=False` is not the protection
	it looks like, because git itself takes options that name a command to run:

	    git ls-remote --heads "--upload-pack=touch /tmp/x; git-upload-pack" /some/repo

	runs `touch` and exits 0. Anything a browser supplies that begins with `-`
	is therefore an argument of git's choosing rather than ours, and the doctype
	validation that used to be the only check runs on save — which this path
	never does. `--` stops option parsing; the patterns stop everything else.
	"""
	url = (git_url or "").strip()
	if not VALID_REMOTE.match(url):
		raise RepoRefused(
			f"{git_url!r} is not a git remote this app will contact. Use git@host:org/repo.git, "
			"ssh://…, or https://…"
		)
	if branch and not VALID_BRANCH.match(branch.strip()):
		raise RepoRefused(f"{branch!r} is not a valid branch name.")

	# `--` first, so neither value can be read as an option even if a pattern
	# is ever loosened.
	argv = ["git", "ls-remote", "--heads", "--", url]
	if branch:
		argv.append(branch.strip())

	code, out, err = _run(argv, timeout=40)
	if code != 0:
		return {"reachable": False, "branch_exists": False, "error": _explain(err), "raw": err[:400]}

	refs = [line.split("\t")[-1].removeprefix("refs/heads/") for line in out.splitlines() if line.strip()]
	return {
		"reachable": True,
		"branch_exists": bool(refs) if branch else True,
		"branches": refs[:50],
		"error": None if (refs or not branch) else f"branch {branch!r} does not exist in that repository",
	}


def _explain(stderr: str) -> str:
	"""Turn git's stderr into something that names the actual problem."""
	text = (stderr or "").lower()
	if "repository not found" in text or "could not read from remote" in text:
		return (
			"Repository not found, or the key that answered is not authorised for it. "
			"GitHub returns the same message for both. Check which identity you "
			"authenticate as for this host."
		)
	if "permission denied" in text:
		return (
			"SSH key rejected. The key offered is not registered with the account that owns this repository."
		)
	if "host key verification failed" in text:
		return (
			"Host key not trusted yet. Connect once interactively, or allow StrictHostKeyChecking=accept-new."
		)
	if "timed out" in text or "timeout" in text:
		return "Timed out reaching the remote. Check outbound network access from this machine."
	if "could not resolve host" in text:
		return "DNS lookup failed for the git host."
	return stderr.splitlines()[0][:200] if stderr else "unknown git failure"


def suggested_ssh_config() -> str:
	"""The exact block to paste, for the reader to place themselves."""
	keys = {k["name"]: k["path"] for k in list_keys()}
	carbonite = keys.get("id_ed25519") or next(iter(keys.values()), "~/.ssh/id_ed25519")
	personal = keys.get("id_rsa") or carbonite

	return "\n\n".join(
		f"Host {alias}\n"
		f"\tHostName github.com\n"
		f"\tUser git\n"
		f"\tIdentityFile {carbonite if org == 'Carbonite-Solutions-Ltd' else personal}\n"
		f"\tIdentitiesOnly yes"
		for org, alias in ORG_ALIASES.items()
	)


def check_git_auth() -> dict:
	"""Full read-only report on whether private clones will work."""
	config = read_ssh_config()
	keys = list_keys()

	hosts = ["github.com"] + [a for a in ORG_ALIASES.values() if a in config["hosts"]]
	probes = [probe_host(host) for host in hosts]

	problems = []
	if not any(k["passphrase_free"] for k in keys):
		problems.append(
			"No passphrase-free key found. Background jobs run without an ssh-agent, "
			"so a clone can never supply a passphrase."
		)
	for key in keys:
		if not key["permissions_ok"]:
			problems.append(f"{key['name']} has permissions {key['permissions']}; ssh requires 0600.")
	if config["missing_aliases"]:
		problems.append(
			f"~/.ssh/config has no {', '.join(config['missing_aliases'])} block, so ssh will offer "
			"keys in default order and GitHub will authenticate you as whichever matches first."
		)
	if not any(p["authenticated_as"] for p in probes):
		problems.append("GitHub did not accept any key over SSH from this machine.")

	return {
		"ssh_config": config,
		"keys": keys,
		"probes": probes,
		"problems": problems,
		"ok": not problems,
		"suggested_ssh_config": suggested_ssh_config(),
	}
