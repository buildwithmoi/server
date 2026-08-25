# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What sshd is ACTUALLY configured to do, as opposed to what the file says.

This is the detector for the thing that caused the incident this whole app
exists because of: SSH accepted passwords, somebody guessed one, and nobody
found out for eight months. Everything else in `server/security/` watches for
what an intruder does after they are in. This watches the door.

TWO THINGS MAKE READING THE CONFIG FILE THE WRONG ANSWER, and both are why
this module shells out instead of parsing /etc/ssh/sshd_config:

  Include.  Ubuntu ships `Include /etc/ssh/sshd_config.d/*.conf` at the TOP of
            the file, and cloud images drop files in there. A setting later in
            the main file does not override an included one -- sshd takes the
            FIRST occurrence of most keywords -- so reading top to bottom gives
            you the opposite of the truth.
  Defaults. A keyword that appears nowhere is not off. `PasswordAuthentication`
            defaults to yes, which is precisely the setting that mattered here.
            A file that never mentions it looks clean and is not.

`sshd -T` answers both: it prints the effective configuration, defaults filled
in and includes resolved. It is the same thing sshd itself will use.

AND ONE THING `sshd -T` STILL WILL NOT TELL YOU, which is why `parse_match_blocks`
exists. Without a `-C` connection spec, `sshd -T` prints the GLOBAL block only,
and silently ignores every `Match` section. A file whose global block says
`PasswordAuthentication no` and whose Match block says `yes` for one group
reports as hardened. The fixture in tests/fixtures/sshd_config_with_match.txt
is exactly that shape, because it is exactly the shape that gets missed.

Frappe-free, like `persistence.py` and `ssh/parser.py` -- which matters more
here than anywhere else in this app, because THIS DEV BOX HAS NO SSHD AT ALL.
Every rule below was built against checked-in fixtures and must be re-verified
on the real server; the collector reports its own absence rather than
returning a confident empty answer.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field

from server.security.persistence import Surface, _hash, _read

#: The keywords worth recording. `sshd -T` prints about fifty and most are
#: irrelevant to whether the door is locked; storing all of them would mean
#: alerting on a cipher-order change after an OpenSSH upgrade.
WATCHED = (
	"port",
	"listenaddress",
	"permitrootlogin",
	"passwordauthentication",
	"kbdinteractiveauthentication",
	"pubkeyauthentication",
	"permitemptypasswords",
	"permituserenvironment",
	"usepam",
	"maxauthtries",
	"logingracetime",
	"allowtcpforwarding",
	"allowagentforwarding",
	"gatewayports",
	"permittunnel",
	"disableforwarding",
	"x11forwarding",
	"loglevel",
	"authorizedkeysfile",
	"allowusers",
	"denyusers",
	"allowgroups",
	"denygroups",
	"ciphers",
	"macs",
	"kexalgorithms",
	"hostbasedauthentication",
	"ignorerhosts",
	"strictmodes",
)

#: Keywords sshd legitimately prints more than once.
MULTI_VALUE = frozenset({"listenaddress", "hostkey", "port", "acceptenv", "subsystem", "include"})

CONFIG_FILE = "/etc/ssh/sshd_config"
CONFIG_DIRECTORY = "/etc/ssh/sshd_config.d"

_MATCH_LINE = re.compile(r"^\s*match\s+(?P<criteria>.+?)\s*$", re.IGNORECASE)
_SETTING_LINE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9]*)\s+(?P<value>.+?)\s*$")


@dataclass(frozen=True)
class MatchBlock:
	"""A conditional override in sshd_config, and what it changes.

	`sshd -T` does not show these, so they are read from the file directly --
	the one place in this module where the file is more truthful than the
	binary.
	"""

	criteria: str
	settings: dict = field(default_factory=dict)
	line_number: int = 0

	def as_dict(self) -> dict:
		return {"criteria": self.criteria, "settings": self.settings, "line_number": self.line_number}


@dataclass(frozen=True)
class Snapshot:
	#: keyword -> list of values, as sshd resolved them.
	effective: dict = field(default_factory=dict)
	match_blocks: tuple[MatchBlock, ...] = ()
	#: path -> sha256, so a config edit is visible even if nothing we watch changed.
	file_hashes: dict = field(default_factory=dict)
	#: sha256 over the WATCHED effective settings. Distinct from the file
	#: hashes on purpose: cloud-init rewriting a drop-in changes the merged
	#: value with no edit to the file anyone would think to look at, and an
	#: OpenSSH upgrade changes defaults with no file edit at all.
	effective_hash: str = ""
	surfaces: tuple[Surface, ...] = ()

	def get(self, key: str, default: str = "") -> str:
		values = self.effective.get(key)
		return values[0] if values else default

	def all(self, key: str) -> list[str]:
		return list(self.effective.get(key, ()))


def parse_effective(text: str) -> dict[str, list[str]]:
	"""Parse `sshd -T` output.

	The format is deliberately simple -- lowercase keyword, space, value -- but
	several keywords repeat, and flattening those to the last one seen loses
	the second listen address, which is how a host ends up listening somewhere
	nobody meant it to.
	"""
	settings: dict[str, list[str]] = {}
	for line in text.splitlines():
		line = line.strip()
		if not line or line.startswith("#"):
			continue
		key, _, value = line.partition(" ")
		key = key.strip().lower()
		if not key:
			continue
		settings.setdefault(key, []).append(value.strip())
	return settings


def parse_match_blocks(text: str) -> list[MatchBlock]:
	"""Every `Match` section in a raw sshd_config, and what it overrides.

	THE POINT OF THIS FUNCTION. `sshd -T` reports the global block and pretends
	Match sections do not exist. A config whose global block says
	`PasswordAuthentication no` and which re-enables it for one group is,
	according to `sshd -T`, a hardened server. It is not, and the group that
	gets the exception is usually the one with the weakest passwords -- a
	deploy or CI account nobody rotates.

	Everything up to the first `Match` is the global block and is skipped here;
	`sshd -T` already covers it and covers it better.
	"""
	blocks: list[MatchBlock] = []
	criteria = ""
	settings: dict[str, str] = {}
	started_at = 0

	def flush():
		if criteria:
			blocks.append(MatchBlock(criteria=criteria, settings=dict(settings), line_number=started_at))

	for number, raw in enumerate(text.splitlines(), start=1):
		line = raw.split("#", 1)[0].rstrip()
		if not line.strip():
			continue

		match = _MATCH_LINE.match(line)
		if match:
			flush()
			criteria = match.group("criteria")
			settings = {}
			started_at = number
			continue

		if not criteria:
			# Still in the global block.
			continue

		setting = _SETTING_LINE.match(line)
		if setting:
			settings[setting.group("key").lower()] = setting.group("value")

	flush()
	return blocks


def collect_effective() -> tuple[dict[str, list[str]], list[Surface]]:
	"""Ask sshd what it is actually configured to do.

	`-T` needs to read the host keys, so it usually needs root. When it cannot,
	that is recorded as an unreadable surface rather than an empty config --
	the difference between "SSH is wide open" and "we could not tell" is the
	entire value of this check, and reporting the second as the first would be
	worse than not checking.
	"""
	if not _which("sshd"):
		return {}, [
			Surface(
				"sshd",
				"sshd -T",
				False,
				"sshd is not installed on this host",
				0,
			)
		]

	try:
		result = subprocess.run(  # noqa: S603
			["sshd", "-T"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=30,
			check=False,
		)
	except (OSError, subprocess.SubprocessError) as exc:
		return {}, [Surface("sshd", "sshd -T", False, str(exc), 0)]

	if result.returncode != 0:
		reason = (result.stderr or "").strip().splitlines()
		return {}, [
			Surface("sshd", "sshd -T", False, reason[-1] if reason else f"exit {result.returncode}", 0)
		]

	settings = parse_effective(result.stdout)
	return settings, [Surface("sshd", "sshd -T", True, "", len(settings))]


def _which(program: str) -> str:
	for directory in os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").split(os.pathsep):
		candidate = os.path.join(directory, program)
		if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
			return candidate
	# sshd lives in /usr/sbin, which is not on a normal user's PATH.
	for candidate in ("/usr/sbin/sshd", "/sbin/sshd"):
		if os.path.isfile(candidate):
			return candidate
	return ""


def collect_config_files() -> tuple[dict[str, str], list[MatchBlock], list[Surface]]:
	"""Hash the config files, and read Match blocks out of them.

	Hashed, never stored: an sshd_config can name internal addresses, bastion
	hosts and account names, and this app must not become the single richest
	target on the estate. The hash answers "did this change", which is the
	question, and answers nothing else.
	"""
	hashes: dict[str, str] = {}
	blocks: list[MatchBlock] = []
	surfaces: list[Surface] = []

	paths = [CONFIG_FILE]
	if os.path.isdir(CONFIG_DIRECTORY):
		try:
			paths.extend(
				sorted(
					os.path.join(CONFIG_DIRECTORY, name)
					for name in os.listdir(CONFIG_DIRECTORY)
					if name.endswith(".conf")
				)
			)
		except OSError as exc:
			surfaces.append(Surface("sshd-config", CONFIG_DIRECTORY, False, str(exc), 0))

	for path in paths:
		data, error = _read(path)
		if data is None:
			surfaces.append(Surface("sshd-config", path, False, error, 0))
			continue
		hashes[path] = _hash(data)
		blocks.extend(parse_match_blocks(data.decode("utf-8", "replace")))
		surfaces.append(Surface("sshd-config", path, True, "", 1))

	return hashes, blocks, surfaces


def effective_hash(settings: dict) -> str:
	"""Hash the settings worth watching, in a stable order.

	Only WATCHED: `sshd -T` prints about fifty values and most are irrelevant
	to whether the door is locked. Hashing all of them would raise a drift
	finding every time an OpenSSH upgrade reordered the default cipher list,
	which is how a drift check gets switched off.
	"""
	import hashlib

	canonical = "\n".join(
		f"{key} {value}"
		for key in WATCHED
		if key in settings
		for value in sorted(settings[key])
	)
	return hashlib.sha256(canonical.encode()).hexdigest() if canonical else ""


def collect() -> Snapshot:
	"""Everything this module can see about sshd, and what it could not."""
	effective, surfaces = collect_effective()
	hashes, blocks, config_surfaces = collect_config_files()
	return Snapshot(
		effective=effective,
		match_blocks=tuple(blocks),
		file_hashes=hashes,
		effective_hash=effective_hash(effective),
		surfaces=tuple(surfaces + config_surfaces),
	)
