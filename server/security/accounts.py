# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Who can log in to this host, and with what.

The incident behind this module left a rogue account called `mysqld` — UID
1003, a bash shell, no home directory — sitting in `/etc/passwd` for months.
It reads as the MariaDB service account at a glance, and that is the whole
point of the name. Nothing on the box ever mentioned it, because nothing was
looking at the account list.

The signature is unusually clean: a real service account has `/usr/sbin/nologin`
and a system UID. An account that impersonates a service name while carrying a
login shell has no legitimate explanation, and neither does one whose home
directory does not exist.

TWO RULES ABOUT SECRETS, both absolute.

**Password hashes are never read.** `/etc/shadow` is consulted only for whether
a password is set, locked or absent, and when it last changed. The hash itself
is not read, not stored, and not hashed-and-stored. An app that watches for
compromise must not become the richest target on the estate.

**Keys are recorded by fingerprint.** Never the key material. A fingerprint is
enough to say "this is the same key as yesterday" and to join against the SSH
login records, which already capture the fingerprint used on each login — so
"this key has been used from these addresses" comes free.

Frappe-free: parsing and judgement both test with no site.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field

#: Below this, an account is a system account created by a package. Debian's
#: convention, and the reason UID 1003 on a server nobody added a user to is
#: itself worth a look.
SYSTEM_UID_MAX = 999

#: Shells that mean "this account cannot log in", which is what a genuine
#: service account has.
#: `/bin/sync` is Debian's — the account runs sync(1) and exits, and treating
#: it as a login shell would flag a stock account on every host forever.
NOLOGIN_SHELLS = (
	"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync", "",
)

#: Groups that confer root.
PRIVILEGED_GROUPS = ("sudo", "admin", "wheel", "root")

#: Names that read as a service or a daemon. An account called one of these
#: with a login shell is the `mysqld` signature.
SERVICE_NAMES = (
	"mysql", "mysqld", "mariadb", "postgres", "postgresql", "redis", "mongodb",
	"www-data", "nginx", "apache", "httpd", "systemd", "dbus", "daemon", "syslog",
	"ftp", "mail", "news", "backup", "kernel", "docker", "nobody",
)

PASSWORD_SET = "set"
PASSWORD_LOCKED = "locked"
PASSWORD_NONE = "none"
PASSWORD_UNKNOWN = "unknown"


@dataclass(frozen=True)
class Account:
	"""One line of /etc/passwd, plus what can be said about it safely."""

	username: str
	uid: int
	gid: int
	shell: str
	home: str
	gecos: str = ""
	home_exists: bool = False
	groups: tuple[str, ...] = ()
	#: set | locked | none | unknown. Never the hash.
	password_status: str = PASSWORD_UNKNOWN
	password_changed: str = ""

	@property
	def can_log_in(self) -> bool:
		return self.shell not in NOLOGIN_SHELLS

	@property
	def is_system(self) -> bool:
		return self.uid <= SYSTEM_UID_MAX

	@property
	def privileged(self) -> bool:
		return bool(set(self.groups) & set(PRIVILEGED_GROUPS)) or self.uid == 0

	def as_dict(self) -> dict:
		return {
			**self.__dict__,
			"groups": list(self.groups),
			"can_log_in": self.can_log_in,
			"is_system": self.is_system,
			"privileged": self.privileged,
		}


@dataclass(frozen=True)
class Key:
	"""One entry in an authorized_keys file, by fingerprint only."""

	account: str
	path: str
	fingerprint: str
	key_type: str
	comment: str = ""
	options: str = ""

	def as_dict(self) -> dict:
		return self.__dict__.copy()


@dataclass(frozen=True)
class Surface:
	"""Whether something this module needs to read could be read."""

	kind: str
	path: str
	readable: bool
	reason: str = ""
	items_found: int = 0

	def as_dict(self) -> dict:
		return self.__dict__.copy()


# ----------------------------------------------------------------------
# /etc/passwd, /etc/group, /etc/shadow
# ----------------------------------------------------------------------


def _read_lines(path: str) -> tuple[list[str], str]:
	try:
		with open(path, encoding="utf-8", errors="replace") as handle:
			return handle.read().splitlines(), ""
	except PermissionError:
		return [], "permission denied"
	except FileNotFoundError:
		return [], "does not exist"
	except OSError as exc:
		return [], str(exc)


def parse_passwd(lines: list[str]) -> list[Account]:
	accounts = []
	for line in lines:
		parts = line.split(":")
		if len(parts) < 7 or not parts[0]:
			continue
		try:
			uid, gid = int(parts[2]), int(parts[3])
		except ValueError:
			continue
		accounts.append(
			Account(
				username=parts[0],
				uid=uid,
				gid=gid,
				gecos=parts[4],
				home=parts[5],
				shell=parts[6],
				home_exists=os.path.isdir(parts[5]) if parts[5] else False,
			)
		)
	return accounts


def parse_group(lines: list[str]) -> dict[str, list[str]]:
	"""Map each username to the groups naming it as a member."""
	memberships: dict[str, list[str]] = {}
	for line in lines:
		parts = line.split(":")
		if len(parts) < 4 or not parts[0]:
			continue
		for member in parts[3].split(","):
			member = member.strip()
			if member:
				memberships.setdefault(member, []).append(parts[0])
	return memberships


def parse_shadow(lines: list[str]) -> dict[str, tuple[str, str]]:
	"""Password STATUS per account. The hash is deliberately not returned.

	`!` or `*` in the hash field means locked or unusable; an empty field means
	no password at all, which is worse than a weak one. The hash itself is read
	from the line and immediately discarded — it is never returned, stored, or
	included in any record this app writes.
	"""
	status: dict[str, tuple[str, str]] = {}
	for line in lines:
		parts = line.split(":")
		if len(parts) < 3 or not parts[0]:
			continue
		secret = parts[1]
		if secret in ("", "!", "*", "!!", "!*"):
			state = PASSWORD_NONE if secret == "" else PASSWORD_LOCKED
		else:
			state = PASSWORD_SET
		status[parts[0]] = (state, parts[2])
	return status


def collect_accounts() -> tuple[list[Account], list[Surface]]:
	"""Every account on the host, with group and password status folded in."""
	surfaces: list[Surface] = []

	passwd_lines, reason = _read_lines("/etc/passwd")
	if reason:
		return [], [Surface("accounts", "/etc/passwd", False, reason)]
	surfaces.append(Surface("accounts", "/etc/passwd", True, items_found=len(passwd_lines)))

	group_lines, group_reason = _read_lines("/etc/group")
	if group_reason:
		surfaces.append(Surface("groups", "/etc/group", False, group_reason))
	memberships = parse_group(group_lines)

	shadow_lines, shadow_reason = _read_lines("/etc/shadow")
	if shadow_reason:
		# Expected when not running as root. Reported rather than glossed over:
		# without it, "a password was set on a key-only account" cannot be seen.
		surfaces.append(Surface("passwords", "/etc/shadow", False, shadow_reason))
	shadow = parse_shadow(shadow_lines)

	accounts = []
	for account in parse_passwd(passwd_lines):
		state, changed = shadow.get(account.username, (PASSWORD_UNKNOWN, ""))
		groups = tuple(sorted(memberships.get(account.username, [])))
		accounts.append(
			Account(
				**{
					**account.__dict__,
					"groups": groups,
					"password_status": state,
					"password_changed": changed,
				}
			)
		)
	return accounts, surfaces


# ----------------------------------------------------------------------
# authorized_keys
# ----------------------------------------------------------------------

_KEY_LINE = re.compile(
	r"^(?P<options>.*?\s)?(?P<type>(?:ssh|ecdsa|sk)-[\w@.-]+)\s+(?P<blob>[A-Za-z0-9+/=]+)\s*(?P<comment>.*)$"
)


def fingerprint(key_type: str, blob: str) -> str:
	"""The SHA256 fingerprint OpenSSH prints, computed without shelling out.

	`ssh-keygen -lf` needs a file and a subprocess per key; the fingerprint is
	just a base64 SHA-256 of the decoded blob, so this is both faster and
	usable on a key that is not on disk.
	"""
	try:
		raw = base64.b64decode(blob, validate=True)
	except Exception:  # noqa: BLE001 - a malformed key is not an error here
		return ""
	digest = hashlib.sha256(raw).digest()
	return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def parse_authorized_keys(text: str, account: str, path: str) -> list[Key]:
	keys = []
	for raw in text.splitlines():
		line = raw.strip()
		if not line or line.startswith("#"):
			continue
		match = _KEY_LINE.match(line)
		if not match:
			continue
		printable = fingerprint(match["type"], match["blob"])
		if not printable:
			continue
		keys.append(
			Key(
				account=account,
				path=path,
				fingerprint=printable,
				key_type=match["type"],
				comment=(match["comment"] or "").strip()[:200],
				options=(match["options"] or "").strip()[:200],
			)
		)
	return keys


def collect_keys(accounts: list[Account]) -> tuple[list[Key], list[Surface]]:
	"""Every authorized_keys on the host, by fingerprint.

	Driven from the account list rather than from a glob of `/home`, so a key
	file belonging to an account with a home somewhere unusual is not missed —
	which is exactly where someone would put one.
	"""
	keys: list[Key] = []
	surfaces: list[Surface] = []

	for account in accounts:
		if not account.home:
			continue
		for name in ("authorized_keys", "authorized_keys2"):
			path = os.path.join(account.home, ".ssh", name)
			if not os.path.exists(path):
				continue
			try:
				with open(path, encoding="utf-8", errors="replace") as handle:
					text = handle.read()
			except PermissionError:
				surfaces.append(Surface("keys", path, False, "permission denied"))
				continue
			except OSError as exc:
				surfaces.append(Surface("keys", path, False, str(exc)))
				continue
			found = parse_authorized_keys(text, account.username, path)
			keys.extend(found)
			surfaces.append(Surface("keys", path, True, items_found=len(found)))
	return keys, surfaces


# ----------------------------------------------------------------------
# Last login
# ----------------------------------------------------------------------


def last_logins() -> dict[str, str]:
	"""When each account last logged in, per `lastlog`.

	Used for the stale-account check: an account nobody has used in three
	months that still has a working shell is an unnecessary way in.
	"""
	try:
		result = subprocess.run(  # noqa: S603
			["lastlog"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=30,
			check=False,
		)
	except (OSError, subprocess.SubprocessError):
		return {}
	if result.returncode != 0:
		return {}

	seen: dict[str, str] = {}
	for line in result.stdout.splitlines()[1:]:
		parts = line.split(None, 1)
		if len(parts) == 2:
			seen[parts[0]] = parts[1].strip()
	return seen


@dataclass(frozen=True)
class Snapshot:
	"""Everything this module can say about who can log in, in one object."""

	accounts: list[Account] = field(default_factory=list)
	keys: list[Key] = field(default_factory=list)
	surfaces: list[Surface] = field(default_factory=list)
	#: Username to the last-login line from `lastlog`, where it is available.
	last_login: dict = field(default_factory=dict)

	@property
	def blind_spots(self) -> list[Surface]:
		return [s for s in self.surfaces if not s.readable and s.reason != "does not exist"]


def collect() -> Snapshot:
	"""Accounts, keys, and how much of it could actually be read."""
	accounts, surfaces = collect_accounts()
	keys, key_surfaces = collect_keys(accounts)
	return Snapshot(
		accounts=accounts,
		keys=keys,
		surfaces=surfaces + key_surfaces,
		last_login=last_logins(),
	)
