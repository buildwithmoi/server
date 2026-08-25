# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The security state of the Frappe sites this bench serves.

Everything else in `server/security/` watches the operating system. This
watches the application on top of it, which is where the valuable things
actually are -- the database credentials, the encryption key that unlocks every
stored password, and the backups that are supposed to be the way back from a
bad day.

THE FINDING THAT PROMPTED THIS MODULE, verified on this bench rather than
imagined. Every time frappe takes a backup it writes a
`*-site_config_backup.json` beside the dump, containing `db_password` and
`encryption_key` in plain text, at mode 0644, in a directory chain that is
world-traversable. Any account on the host can read them. The encryption key
is the one that decrypts every `Password` field in the site -- which, in this
app, includes the database root password used for restores and the token used
to forward findings off the box. A local foothold becomes every credential the
site has, without touching the database at all.

WHAT THIS MODULE WILL NEVER DO. It never reads a secret's VALUE, never stores
one, and never puts one in a finding. It records which KEYS are secrets, what
the file's mode is, and who can reach it. The spec is explicit that this app
must not become the single richest target on the estate, and a security
scanner that helpfully collects every password into one doctype is exactly
that.

Frappe-free: it reads files and directories. The parts that need a database --
who has System Manager, which accounts hold API keys -- are gathered in
`watch.py` and passed in as plain data, so everything judged here stays
testable with no site.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field

from server.bench.siteconfig import is_secret
from server.security.persistence import Surface

KIND_CONFIG = "site-config"
KIND_BACKUP = "backup"

#: Config settings that change what the application will let someone do.
#: The value is (dangerous_value, why it matters) and the rules decide severity.
DANGEROUS_SETTINGS = {
	"developer_mode": 1,
	"allow_tests": True,
	"server_script_enabled": 1,
	"disable_prepared_report": None,
	"maintenance_mode": None,
}

#: A backup older than this and nobody has a recent way back. Not a hard
#: schedule -- frappe's own backup cron is daily, so a day and a half allows a
#: missed run without crying about it.
BACKUP_STALE_HOURS = 36


@dataclass(frozen=True)
class ConfigFile:
	"""One JSON configuration file, described without being quoted."""

	path: str
	#: Octal mode, e.g. "0644".
	mode: str
	owner: str
	#: Whether group or other can read it.
	world_readable: bool
	group_readable: bool
	#: Names only. Never values.
	secret_keys: tuple[str, ...] = ()
	#: Non-secret settings worth judging, by name.
	settings: dict = field(default_factory=dict)
	#: Whether every directory above it can be traversed by others.
	path_traversable: bool = True

	@property
	def exposes_secrets(self) -> bool:
		return bool(self.secret_keys) and (self.world_readable or self.group_readable)

	def as_dict(self) -> dict:
		return {
			"path": self.path,
			"mode": self.mode,
			"owner": self.owner,
			"world_readable": self.world_readable,
			"group_readable": self.group_readable,
			"secret_keys": list(self.secret_keys),
			"settings": self.settings,
			"path_traversable": self.path_traversable,
			"exposes_secrets": self.exposes_secrets,
		}


@dataclass(frozen=True)
class BackupState:
	"""What the most recent backups look like, without opening the dumps."""

	site: str
	newest_age_hours: float | None = None
	count: int = 0
	newest_has_files: bool = False
	newest_encrypted: bool = False
	newest_size: int = 0
	#: Config sidecars found beside the dumps, which are the exposure risk.
	config_sidecars: tuple[str, ...] = ()

	def as_dict(self) -> dict:
		return {
			"site": self.site,
			"newest_age_hours": self.newest_age_hours,
			"count": self.count,
			"newest_has_files": self.newest_has_files,
			"newest_encrypted": self.newest_encrypted,
			"newest_size": self.newest_size,
			"config_sidecars": list(self.config_sidecars),
		}


@dataclass(frozen=True)
class Snapshot:
	configs: tuple[ConfigFile, ...] = ()
	backups: tuple[BackupState, ...] = ()
	#: Whatever the frappe layer gathered: privileged users, API keys, and so
	#: on. A plain dict so this module never imports frappe.
	accounts: dict = field(default_factory=dict)
	surfaces: tuple[Surface, ...] = ()


def _owner_name(info: os.stat_result) -> str:
	import pwd

	try:
		return pwd.getpwuid(info.st_uid).pw_name
	except (KeyError, OSError):
		return str(info.st_uid)


def _others_can_traverse(path: str, stop_at: str = "/") -> bool:
	"""Can a non-owner walk down to this file?

	Mode 0644 on a file inside a 0700 directory is not exposed, and reporting
	it as such would be a false alarm on a correctly locked-down bench. The
	only honest answer walks the chain.
	"""
	current = os.path.dirname(os.path.abspath(path))
	while True:
		try:
			mode = os.stat(current).st_mode
		except OSError:
			return False
		if not mode & (stat.S_IXOTH | stat.S_IXGRP):
			return False
		if current in (stop_at, "/"):
			return True
		parent = os.path.dirname(current)
		if parent == current:
			return True
		current = parent


def read_config_file(path: str) -> ConfigFile | None:
	"""Describe a config file: its mode, its secret KEY NAMES, its settings.

	Values of secret keys are never read into the returned object. The file
	must be parsed to know which keys exist, so the values pass through memory
	-- but nothing keeps them, and nothing downstream can ask for them.
	"""
	try:
		info = os.stat(path)
		with open(path, encoding="utf-8") as handle:
			raw = json.load(handle)
	except (OSError, ValueError):
		return None

	if not isinstance(raw, dict):
		return None

	secrets = tuple(sorted(key for key in raw if is_secret(key)))
	settings = {key: value for key, value in raw.items() if not is_secret(key) and key in DANGEROUS_SETTINGS}

	return ConfigFile(
		path=path,
		mode=oct(stat.S_IMODE(info.st_mode)).replace("0o", "0"),
		owner=_owner_name(info),
		world_readable=bool(info.st_mode & stat.S_IROTH),
		group_readable=bool(info.st_mode & stat.S_IRGRP),
		secret_keys=secrets,
		settings=settings,
		path_traversable=_others_can_traverse(path),
	)


def collect_configs(bench_path: str, sites: list[str]) -> tuple[list[ConfigFile], list[Surface]]:
	"""Every configuration file that holds a credential.

	Including the backup sidecars, which is the point: `site_config.json` is
	usually noticed and locked down, and the copies frappe writes next to every
	dump usually are not.
	"""
	configs: list[ConfigFile] = []
	surfaces: list[Surface] = []

	candidates = [os.path.join(bench_path, "sites", "common_site_config.json")]
	for site in sites:
		site_dir = os.path.join(bench_path, "sites", site)
		candidates.append(os.path.join(site_dir, "site_config.json"))
		backups = os.path.join(site_dir, "private", "backups")
		if os.path.isdir(backups):
			try:
				candidates.extend(
					os.path.join(backups, name)
					for name in sorted(os.listdir(backups))
					if name.endswith("site_config_backup.json")
				)
			except OSError as exc:
				surfaces.append(Surface(KIND_CONFIG, backups, False, str(exc), 0))

	found = 0
	for path in candidates:
		if not os.path.exists(path):
			continue
		described = read_config_file(path)
		if described is None:
			surfaces.append(Surface(KIND_CONFIG, path, False, "could not be read or parsed", 0))
			continue
		configs.append(described)
		found += 1

	surfaces.append(Surface(KIND_CONFIG, os.path.join(bench_path, "sites"), True, "", found))
	return configs, surfaces


def collect_backups(bench_path: str, sites: list[str], now: float) -> tuple[list[BackupState], list[Surface]]:
	"""How recent and how complete each site's backups are.

	Deliberately does NOT open the dumps. Verifying a multi-gigabyte backup by
	decompressing it is a real check and an expensive one, and doing it on the
	ordinary detector schedule would put a server under sustained I/O to learn
	something that changes once a day. What this answers is the question that
	actually goes wrong silently: is there a recent one at all.
	"""
	from server.bench import restore

	states: list[BackupState] = []
	surfaces: list[Surface] = []

	for site in sites:
		directory = os.path.join(bench_path, "sites", site, "private", "backups")
		if not os.path.isdir(directory):
			surfaces.append(Surface(KIND_BACKUP, directory, True, "no backup directory", 0))
			states.append(BackupState(site=site, count=0))
			continue

		try:
			# Only this site's own directory: `list_backups` deliberately
			# includes dropped-in files from anywhere, which is right for
			# choosing a restore and wrong for asking "is this site being
			# backed up" -- a file someone copied in once would answer yes
			# forever.
			sets = restore.list_backups(
				bench_path, site, directories=[(restore.own_backup_directory(bench_path, site), "site")]
			)
		except Exception as exc:  # noqa: BLE001
			surfaces.append(Surface(KIND_BACKUP, directory, False, f"{type(exc).__name__}: {exc}", 0))
			continue

		sidecars = tuple(
			name for name in sorted(os.listdir(directory)) if name.endswith("site_config_backup.json")
		)

		if not sets:
			states.append(BackupState(site=site, count=0, config_sidecars=sidecars))
			surfaces.append(Surface(KIND_BACKUP, directory, True, "", 0))
			continue

		newest = sets[0]
		try:
			age = max(0.0, (now - os.path.getmtime(newest.database)) / 3600.0)
		except OSError:
			age = None

		states.append(
			BackupState(
				site=site,
				newest_age_hours=age,
				count=len(sets),
				newest_has_files=newest.has_files,
				newest_encrypted=newest.encrypted,
				newest_size=newest.size,
				config_sidecars=sidecars,
			)
		)
		surfaces.append(Surface(KIND_BACKUP, directory, True, "", len(sets)))

	return states, surfaces


def collect(bench_path: str, sites: list[str], accounts: dict | None = None, now: float | None = None) -> Snapshot:
	import time

	configs, config_surfaces = collect_configs(bench_path, sites)
	backups, backup_surfaces = collect_backups(bench_path, sites, now or time.time())
	return Snapshot(
		configs=tuple(configs),
		backups=tuple(backups),
		accounts=accounts or {},
		surfaces=tuple(config_surfaces + backup_surfaces),
	)
