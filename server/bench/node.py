# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Putting the node a bench actually needs in front of the one the shell has.

`bench get-app` does not only clone: unless it is told to skip assets it runs
yarn, and yarn runs against whatever `node` is first on PATH. On this box that
is v18.20.8, because that is what the login shell's nvm default points at —
and Frappe v16 declares `"engines": {"node": ">=24"}`. The failure is a
`SyntaxError` about `styleText` not being exported, thrown from inside a
dependency, minutes into a clone that otherwise worked. Nothing in it says
"wrong node".

WHY THIS DOES NOT RUN `nvm use 24`.

`nvm` is not a program. It is a shell function defined by sourcing
`$NVM_DIR/nvm.sh`, so there is nothing to exec, and the worker's subprocesses
get `stdin=DEVNULL` and no login shell to source it in. Running it would mean
routing every bench command through `bash -lc`, which is a real cost: the
argv stops being a list Python passes through untouched.

But `nvm use 24` does exactly one thing that matters here — it puts that
version's `bin` at the front of PATH. So this does that directly. The result is
identical, needs no shell, and is checkable: `select()` and `activate()` are
plain functions over plain data.

WHY THE VERSION IS ASKED OF THE BENCH RATHER THAN HARDCODED.

`16 → 24` is true today and was `16 → 20` a year ago. Every bench carries the
answer in `apps/frappe/package.json`, written by the frappe release the bench
is actually on — measured here: v16.31.0 says `>=24`, v15.116.0 says `>=18`.
The version-number table is only the fallback for a bench that does not exist
yet, which is the provisioning case.

Frappe-free, like `ssl.py` and `provision.py`: no site, no database.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass

#: Only consulted when there is no bench to ask — i.e. while provisioning one.
#: Read from frappe's own `package.json` in every other case.
FALLBACK_MAJOR = {"16": 24, "15": 18, "14": 16}

#: `>=24`, `^24.1.0`, `24.x`, `>=20 <25` — the first number is the floor in all
#: of them, which is the only part of a semver range this needs.
_FIRST_MAJOR = re.compile(r"(\d+)")

_NVM_VERSION_DIR = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


@dataclass(frozen=True)
class Runtime:
	"""One installed node."""

	version: str
	major: int
	bin_dir: str

	@property
	def label(self) -> str:
		return f"v{self.version}"


@dataclass(frozen=True)
class Choice:
	"""What was decided, in enough detail to explain it in a job log."""

	required: int | None
	chosen: Runtime | None
	before: Runtime | None
	note: str
	#: False only when we positively established that what will run is too old.
	#: An undetectable node is NOT a refusal — see `satisfied()` below.
	satisfied: bool = True

	@property
	def changed(self) -> bool:
		return bool(self.chosen and (not self.before or self.chosen.bin_dir != self.before.bin_dir))


def required_major(bench_path: str | None = None, frappe_version: str | None = None) -> int | None:
	"""The lowest node major this bench's frappe will accept.

	Asks the bench first. `frappe_version` is the fallback and is used on its
	own while provisioning, when there is no bench yet to ask.
	"""
	if bench_path:
		manifest = os.path.join(bench_path, "apps", "frappe", "package.json")
		try:
			with open(manifest, encoding="utf-8") as handle:
				declared = (json.load(handle).get("engines") or {}).get("node") or ""
			found = _FIRST_MAJOR.search(declared)
			if found:
				return int(found.group(1))
		except (OSError, ValueError, AttributeError):
			# A bench mid-clone has no package.json, and a malformed one is not
			# worth failing a job over. Fall through to the table.
			pass

	if frappe_version:
		return FALLBACK_MAJOR.get(str(frappe_version).strip().split(".")[0])
	return None


def versions_dir(env: dict[str, str] | None = None) -> str:
	env = env if env is not None else os.environ
	nvm_dir = env.get("NVM_DIR") or os.path.join(os.path.expanduser("~"), ".nvm")
	return os.path.join(nvm_dir, "versions", "node")


def installed(directory: str | None = None) -> list[Runtime]:
	"""Every node nvm has, newest first."""
	directory = directory or versions_dir()
	found: list[Runtime] = []
	try:
		entries = os.listdir(directory)
	except OSError:
		return []

	for entry in entries:
		match = _NVM_VERSION_DIR.match(entry)
		if not match:
			continue
		bin_dir = os.path.join(directory, entry, "bin")
		if not os.path.isfile(os.path.join(bin_dir, "node")):
			continue
		found.append(Runtime(version=entry[1:], major=int(match.group(1)), bin_dir=bin_dir))

	return sorted(found, key=lambda r: tuple(int(p) for p in r.version.split(".")), reverse=True)


def select(required: int | None, available: list[Runtime]) -> Runtime | None:
	"""Pick the node to run with.

	Prefers the newest of the EXACT major asked for, not simply the newest
	installed. `>=18` on a v15 bench is a floor, not an invitation to run it on
	24 — the bench was built, tested and its lockfile resolved against 18, and
	silently moving it forward is a change nobody asked for. Only when the exact
	major is absent does this go up to the lowest one that still satisfies.
	"""
	if required is None or not available:
		return None

	exact = [r for r in available if r.major == required]
	if exact:
		return exact[0]

	satisfying = sorted([r for r in available if r.major > required], key=lambda r: r.major)
	return satisfying[0] if satisfying else None


def on_path(env: dict[str, str]) -> Runtime | None:
	"""Which node a subprocess with this environment would get."""
	for entry in (env.get("PATH") or "").split(os.pathsep):
		candidate = os.path.join(entry, "node")
		if not (os.path.isfile(candidate) and os.access(candidate, os.X_OK)):
			continue
		return Runtime(version=_version_of(candidate), major=_major_of(candidate), bin_dir=entry)
	return None


def activate(env: dict[str, str], required: int | None, available: list[Runtime] | None = None) -> tuple[dict, Choice]:
	"""Return an environment whose node satisfies `required`, and why.

	Never raises and never refuses on its own — it reports. The decision to stop
	a job belongs to the preflight, which knows whether assets are going to be
	built at all.
	"""
	before = on_path(env)
	if required is None:
		return env, Choice(None, None, before, "", satisfied=True)

	available = installed(versions_dir(env)) if available is None else available
	chosen = select(required, available)

	if chosen is None:
		# Nothing installed fits. If what is already on PATH happens to satisfy
		# it — node from apt, or a version outside nvm — then nothing is wrong
		# and nothing needs saying.
		if before and before.major >= required:
			return env, Choice(required, None, before, "", satisfied=True)
		have = ", ".join(r.label for r in available) or "none"
		return (
			env,
			Choice(
				required,
				None,
				before,
				f"This bench needs node {required} or newer and none is installed "
				f"(nvm has: {have}). Install it with: nvm install {required}",
				satisfied=False,
			),
		)

	updated = dict(env)
	# Drop every OTHER nvm version from PATH before prepending. Prepending alone
	# would be enough for `node`, but leaving a stale entry behind means anything
	# that walks PATH looking for a sibling binary can still find the old one.
	root = versions_dir(env)
	kept = [p for p in (env.get("PATH") or "").split(os.pathsep) if p and not _is_other_nvm_bin(p, root, chosen)]
	updated["PATH"] = os.pathsep.join([chosen.bin_dir, *kept])
	updated["NVM_BIN"] = chosen.bin_dir
	updated["NVM_INC"] = os.path.join(os.path.dirname(chosen.bin_dir), "include", "node")
	# nvm itself refuses to run while this is set, because it overrides where
	# npm installs globals and would put them outside the version directory.
	updated.pop("npm_config_prefix", None)
	updated.pop("NPM_CONFIG_PREFIX", None)

	if before and before.bin_dir == chosen.bin_dir:
		return updated, Choice(required, chosen, before, "", satisfied=True)

	was = f" (the shell default is {before.label})" if before else ""
	return (
		updated,
		Choice(
			required,
			chosen,
			before,
			f"Using node {chosen.label} for this bench, which wants {required} or newer{was}.",
			satisfied=True,
		),
	)


# ----------------------------------------------------------------------


def _is_other_nvm_bin(entry: str, root: str, chosen: Runtime) -> bool:
	if entry == chosen.bin_dir:
		return False
	return os.path.normpath(entry).startswith(os.path.normpath(root) + os.sep)


def _major_of(node_binary: str) -> int:
	version = _version_of(node_binary)
	try:
		return int(version.split(".")[0])
	except (ValueError, IndexError):
		return 0


def _version_of(node_binary: str) -> str:
	"""The version, from the path when nvm put it there, otherwise by asking.

	The path is preferred because it costs nothing and cannot hang; `node -v`
	is the fallback for a node that came from apt or was built by hand.
	"""
	parts = os.path.normpath(node_binary).split(os.sep)
	for part in parts:
		match = _NVM_VERSION_DIR.match(part)
		if match:
			return part[1:]

	try:
		out = subprocess.run(
			[node_binary, "--version"],
			capture_output=True,
			text=True,
			timeout=10,
			stdin=subprocess.DEVNULL,
		)
		return (out.stdout or "").strip().lstrip("v") or "unknown"
	except (OSError, subprocess.SubprocessError):
		return "unknown"
