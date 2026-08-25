# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Everything on this host that can start something without a person.

The compromise that motivated this module ran for eight months behind
authentication that was never abused: the attacker did not need to log in
again, because eight systemd units, a timer and a root cron entry kept
restarting the payloads. Login tracking answers "who came in". This answers
"what will run next time nobody is watching", which is where that intrusion
actually lived.

The surfaces are small and enumerable, which is what makes this practical:
systemd units and timers, cron in all its locations, shell init files,
`ld.so.preload`, PAM, sudoers, and loaded kernel modules. A clean host changes
almost none of them, so a diff against a baseline is nearly all signal.

TWO THINGS CARRY THE DESIGN.

**Coverage is reported, never assumed.** Running as the bench user, several of
these paths are unreadable — `/var/spool/cron/crontabs` among them, which is
exactly where a root cron entry re-downloading a miner would live. A collector
that returns "no cron entries" for a directory it could not open is worse than
one that collects nothing, because the empty result reads as "clean". Every
surface reports whether it was actually read, and an unreadable one is a
finding in its own right.

**Package ownership is the discriminator.** Nearly every unit on a normal host
belongs to a dpkg package. The ones that do not are the bench's own, a handful
of local additions — and anything an attacker installed. `dpkg-query -S` costs
about two seconds per invocation regardless of how many paths it is given, so
every path is resolved in ONE call.

Frappe-free: this is filesystem and subprocess work, and it tests against a
temp directory with no site and no database.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field

# ----------------------------------------------------------------------
# What counts as a persistence surface
# ----------------------------------------------------------------------

KIND_UNIT = "systemd-unit"
KIND_TIMER = "systemd-timer"
KIND_CRON = "cron"
KIND_SHELL_INIT = "shell-init"
KIND_PRELOAD = "ld-preload"
KIND_PAM = "pam"
KIND_SUDOERS = "sudoers"
KIND_MODULE = "kernel-module"
KIND_BOOT = "boot"

#: Where systemd units live. `/etc` first: a unit there shadows one in `/usr`,
#: and it is where anything hand-installed lands.
UNIT_DIRECTORIES = (
	"/etc/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
	"/run/systemd/system",
)

#: Every place a scheduled command can hide. The per-user spool is the one that
#: usually cannot be read without root, and the one that matters most.
CRON_FILES = ("/etc/crontab", "/etc/anacrontab")
CRON_DIRECTORIES = (
	"/etc/cron.d",
	"/etc/cron.hourly",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/var/spool/cron/crontabs",
	"/var/spool/cron",
)

SHELL_INIT_FILES = (
	"/etc/profile",
	"/etc/bash.bashrc",
	"/etc/zsh/zshrc",
	"/root/.bashrc",
	"/root/.bash_profile",
	"/root/.profile",
)
SHELL_INIT_DIRECTORIES = ("/etc/profile.d",)

BOOT_FILES = ("/etc/rc.local",)

#: Empty on every clean Debian host, and a classic rootkit hook when it is not.
PRELOAD_FILE = "/etc/ld.so.preload"

PAM_DIRECTORY = "/etc/pam.d"
SUDOERS_FILE = "/etc/sudoers"
SUDOERS_DIRECTORY = "/etc/sudoers.d"

#: Directives worth keeping per unit. Enough to judge a unit without storing it.
_UNIT_KEYS = ("Description", "ExecStart", "ExecStartPre", "User", "Restart", "WantedBy", "Type")
_UNIT_LINE = re.compile(r"^\s*(?P<key>[A-Za-z]+)\s*=\s*(?P<value>.*?)\s*$")

#: Files in a unit directory that are not units.
_UNIT_SUFFIXES = (".service", ".timer", ".socket", ".mount", ".path", ".target")


@dataclass(frozen=True)
class Item:
	"""One thing that can cause code to run."""

	kind: str
	#: Unique within its kind — a unit name, a cron file path, a module name.
	identifier: str
	content_hash: str
	path: str = ""
	#: Owning dpkg package, or "" when nothing owns it. The discriminator.
	package: str = ""
	#: Parsed directives, for the rules to judge without re-reading the file.
	detail: dict = field(default_factory=dict)

	@property
	def package_owned(self) -> bool:
		return bool(self.package)

	def as_dict(self) -> dict:
		return {
			"kind": self.kind,
			"identifier": self.identifier,
			"content_hash": self.content_hash,
			"path": self.path,
			"package": self.package,
			"package_owned": self.package_owned,
			"detail": self.detail,
		}


@dataclass(frozen=True)
class Surface:
	"""Whether a place this module is supposed to look could actually be read.

	The most dangerous outcome here is a confident empty answer. A surface that
	could not be opened is recorded so it can be alerted on, rather than
	silently contributing nothing.
	"""

	kind: str
	path: str
	readable: bool
	reason: str = ""
	items_found: int = 0

	def as_dict(self) -> dict:
		return self.__dict__.copy()


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _hash(data: bytes) -> str:
	return hashlib.sha256(data).hexdigest()


def _read(path: str) -> tuple[bytes | None, str]:
	"""Read a file. Returns (contents, reason-if-unreadable)."""
	try:
		with open(path, "rb") as handle:
			return handle.read(), ""
	except PermissionError:
		return None, "permission denied"
	except FileNotFoundError:
		return None, "does not exist"
	except OSError as exc:
		return None, str(exc)


def _listdir(path: str) -> tuple[list[str], str]:
	try:
		return sorted(os.listdir(path)), ""
	except PermissionError:
		return [], "permission denied"
	except FileNotFoundError:
		return [], "does not exist"
	except OSError as exc:
		return [], str(exc)


#: `/lib` is a symlink to `usr/lib` on a merged-/usr system, and the same for
#: bin and sbin. `realpath` therefore yields `/usr/lib/...` while dpkg still
#: records `/lib/...`, so asking dpkg about the resolved path finds nothing.
#:
#: This was not theoretical: it marked forty stock units on this host as owned
#: by no package, which is the Critical condition. Forty false criticals on a
#: clean box is precisely how an alerting system teaches its one reader to stop
#: reading it.
_MERGED_USR = (("/usr/lib/", "/lib/"), ("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/"))


def _path_spellings(path: str) -> list[str]:
	"""Every way dpkg might have recorded this path."""
	spellings = [path]
	for merged, legacy in _MERGED_USR:
		if path.startswith(merged):
			spellings.append(legacy + path[len(merged) :])
		elif path.startswith(legacy):
			spellings.append(merged + path[len(legacy) :])
	return spellings


def owning_packages(paths: list[str]) -> dict[str, str]:
	"""Map each path to the dpkg package that owns it, if any.

	ONE invocation for every path. `dpkg-query -S` takes about two seconds
	whatever it is asked, so calling it per file would turn a scan of four
	hundred units into a quarter of an hour.
	"""
	if not paths:
		return {}

	# Ask about every spelling, then map the answers back to what was asked.
	asked: dict[str, str] = {}
	for path in paths:
		for spelling in _path_spellings(path):
			asked[spelling] = path

	try:
		result = subprocess.run(  # noqa: S603
			["dpkg-query", "-S", *sorted(asked)],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=120,
			check=False,
		)
	except (OSError, subprocess.SubprocessError):
		return {}

	owned: dict[str, str] = {}
	for line in result.stdout.splitlines():
		# "package: /path" — and "pkg1, pkg2: /path" when several ship it.
		package, _, found = line.partition(": ")
		original = asked.get(found.strip())
		if original:
			owned[original] = package.split(",")[0].strip()
	return owned


def _resolve(path: str) -> str:
	"""Follow a unit symlink to whatever actually provides the content.

	`/etc/systemd/system` is mostly symlinks into `/usr/lib` — that is how
	systemd records "enabled". Hashing the link rather than its target would
	report every enable and disable as a content change.
	"""
	try:
		return os.path.realpath(path)
	except OSError:
		return path


def parse_unit(text: str) -> dict:
	"""Pull the directives worth judging out of a unit file.

	Deliberately not a full INI parse. What matters is what the unit runs, as
	whom, whether it restarts itself, and what it claims to be — the four
	things the rules ask about.
	"""
	detail: dict = {}
	for raw in text.splitlines():
		line = raw.strip()
		if not line or line.startswith(("#", ";", "[")):
			continue
		match = _UNIT_LINE.match(line)
		if not match:
			continue
		key, value = match["key"], match["value"]
		if key not in _UNIT_KEYS:
			continue
		# ExecStart can appear more than once; keep them all, in order.
		if key in detail:
			detail[key] = f"{detail[key]}\n{value}"
		else:
			detail[key] = value
	return detail


# ----------------------------------------------------------------------
# Collectors
# ----------------------------------------------------------------------


def collect_units() -> tuple[list[Item], list[Surface]]:
	"""Every systemd unit and timer, with what it runs and who owns it."""
	items: list[Item] = []
	surfaces: list[Surface] = []
	pending: list[tuple[str, str, str, bytes]] = []

	for directory in UNIT_DIRECTORIES:
		names, reason = _listdir(directory)
		if reason:
			# A missing unit directory is normal; an unreadable one is not.
			if reason != "does not exist":
				surfaces.append(Surface(KIND_UNIT, directory, False, reason))
			continue

		found = 0
		for name in names:
			if not name.endswith(_UNIT_SUFFIXES):
				continue
			path = os.path.join(directory, name)
			if os.path.isdir(path):
				continue
			real = _resolve(path)
			content, read_reason = _read(real)
			if content is None:
				surfaces.append(Surface(KIND_UNIT, path, False, read_reason))
				continue
			pending.append((name, path, real, content))
			found += 1
		surfaces.append(Surface(KIND_UNIT, directory, True, items_found=found))

	owners = owning_packages([real for _, _, real, _ in pending])
	for name, path, real, content in pending:
		items.append(
			Item(
				kind=KIND_TIMER if name.endswith(".timer") else KIND_UNIT,
				identifier=name,
				content_hash=_hash(content),
				path=path,
				package=owners.get(real, ""),
				detail=parse_unit(content.decode("utf-8", errors="replace")),
			)
		)

	# A unit in /etc shadows the same name in /usr; keep the one that wins.
	deduped: dict[tuple[str, str], Item] = {}
	for item in items:
		key = (item.kind, item.identifier)
		if key not in deduped:
			deduped[key] = item
	return list(deduped.values()), surfaces


def collect_cron() -> tuple[list[Item], list[Surface]]:
	"""Every scheduled command, from every location cron reads.

	The per-user spool is usually unreadable without root, and it is the one
	that matters most: a root cron entry re-downloading a payload every few
	hours is the shape this exists to catch. Its unreadability is reported
	rather than glossed over.
	"""
	items: list[Item] = []
	surfaces: list[Surface] = []
	pending: list[tuple[str, str, bytes]] = []

	for path in CRON_FILES:
		content, reason = _read(path)
		if content is None:
			if reason != "does not exist":
				surfaces.append(Surface(KIND_CRON, path, False, reason))
			continue
		pending.append((path, path, content))
		surfaces.append(Surface(KIND_CRON, path, True, items_found=1))

	for directory in CRON_DIRECTORIES:
		names, reason = _listdir(directory)
		if reason:
			if reason != "does not exist":
				surfaces.append(Surface(KIND_CRON, directory, False, reason))
			continue

		found = 0
		for name in names:
			if name.startswith("."):
				continue
			path = os.path.join(directory, name)
			if os.path.isdir(path):
				continue
			content, read_reason = _read(path)
			if content is None:
				surfaces.append(Surface(KIND_CRON, path, False, read_reason))
				continue
			pending.append((path, path, content))
			found += 1
		surfaces.append(Surface(KIND_CRON, directory, True, items_found=found))

	owners = owning_packages([path for _, path, _ in pending])
	for identifier, path, content in pending:
		items.append(
			Item(
				kind=KIND_CRON,
				identifier=identifier,
				content_hash=_hash(content),
				path=path,
				package=owners.get(path, ""),
				detail={"lines": _cron_commands(content.decode("utf-8", errors="replace"))},
			)
		)
	return items, surfaces


def _cron_commands(text: str) -> list[str]:
	"""The command lines of a crontab, without comments or environment."""
	commands = []
	for raw in text.splitlines():
		line = raw.strip()
		if not line or line.startswith("#"):
			continue
		# Skip `NAME=value` environment settings, which are not schedules.
		if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", line):
			continue
		commands.append(line)
	return commands


def _collect_files(kind: str, files: tuple[str, ...], directories: tuple[str, ...] = ()) -> tuple[list[Item], list[Surface]]:
	"""Hash a fixed set of files and directories. Used by the simple surfaces."""
	items: list[Item] = []
	surfaces: list[Surface] = []
	pending: list[tuple[str, bytes]] = []

	for path in files:
		content, reason = _read(path)
		if content is None:
			if reason != "does not exist":
				surfaces.append(Surface(kind, path, False, reason))
			continue
		pending.append((path, content))
		surfaces.append(Surface(kind, path, True, items_found=1))

	for directory in directories:
		names, reason = _listdir(directory)
		if reason:
			if reason != "does not exist":
				surfaces.append(Surface(kind, directory, False, reason))
			continue
		found = 0
		for name in names:
			path = os.path.join(directory, name)
			if os.path.isdir(path):
				continue
			content, read_reason = _read(path)
			if content is None:
				surfaces.append(Surface(kind, path, False, read_reason))
				continue
			pending.append((path, content))
			found += 1
		surfaces.append(Surface(kind, directory, True, items_found=found))

	owners = owning_packages([path for path, _ in pending])
	for path, content in pending:
		items.append(
			Item(
				kind=kind,
				identifier=path,
				content_hash=_hash(content),
				path=path,
				package=owners.get(path, ""),
			)
		)
	return items, surfaces


def collect_shell_init() -> tuple[list[Item], list[Surface]]:
	return _collect_files(KIND_SHELL_INIT, SHELL_INIT_FILES, SHELL_INIT_DIRECTORIES)


def collect_boot() -> tuple[list[Item], list[Surface]]:
	return _collect_files(KIND_BOOT, BOOT_FILES)


def collect_pam() -> tuple[list[Item], list[Surface]]:
	return _collect_files(KIND_PAM, (), (PAM_DIRECTORY,))


def collect_sudoers() -> tuple[list[Item], list[Surface]]:
	return _collect_files(KIND_SUDOERS, (SUDOERS_FILE,), (SUDOERS_DIRECTORY,))


def collect_preload() -> tuple[list[Item], list[Surface]]:
	"""`/etc/ld.so.preload`, which is absent or empty on every clean host.

	Recorded even when absent, as an item with an empty hash: its APPEARANCE is
	the event, and a surface that only reports what exists cannot alert on
	something coming into existence.
	"""
	content, reason = _read(PRELOAD_FILE)
	if content is None:
		if reason == "does not exist":
			return [
				Item(kind=KIND_PRELOAD, identifier=PRELOAD_FILE, content_hash="", path=PRELOAD_FILE)
			], [Surface(KIND_PRELOAD, PRELOAD_FILE, True, "absent, which is normal")]
		return [], [Surface(KIND_PRELOAD, PRELOAD_FILE, False, reason)]

	return [
		Item(
			kind=KIND_PRELOAD,
			identifier=PRELOAD_FILE,
			content_hash=_hash(content),
			path=PRELOAD_FILE,
			detail={"entries": content.decode("utf-8", errors="replace").split()},
		)
	], [Surface(KIND_PRELOAD, PRELOAD_FILE, True, items_found=1)]


def collect_modules() -> tuple[list[Item], list[Surface]]:
	"""Loaded kernel modules, by name."""
	try:
		result = subprocess.run(  # noqa: S603
			["lsmod"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=30,
			check=False,
		)
	except (OSError, subprocess.SubprocessError) as exc:
		return [], [Surface(KIND_MODULE, "lsmod", False, str(exc))]

	if result.returncode != 0:
		return [], [Surface(KIND_MODULE, "lsmod", False, (result.stderr or "").strip()[:120])]

	items = []
	for line in result.stdout.splitlines()[1:]:
		name = line.split()[0] if line.split() else ""
		if name:
			items.append(Item(kind=KIND_MODULE, identifier=name, content_hash=name))
	return items, [Surface(KIND_MODULE, "lsmod", True, items_found=len(items))]


COLLECTORS = (
	collect_units,
	collect_cron,
	collect_shell_init,
	collect_boot,
	collect_pam,
	collect_sudoers,
	collect_preload,
	collect_modules,
)


def collect() -> tuple[list[Item], list[Surface]]:
	"""Every persistence surface on this host, and how much of it was readable."""
	items: list[Item] = []
	surfaces: list[Surface] = []
	for collector in COLLECTORS:
		try:
			found, seen = collector()
		except Exception as exc:  # noqa: BLE001 - one bad surface must not stop the scan
			surfaces.append(Surface(collector.__name__, "", False, f"{type(exc).__name__}: {exc}"))
			continue
		items.extend(found)
		surfaces.extend(seen)
	return items, surfaces
