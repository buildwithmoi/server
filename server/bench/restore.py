# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Restoring a site from a backup.

Restore is the most destructive thing this app can do: `bench restore` drops the
site's database and replaces it, and there is no undo. Everything here exists to
make the safe path the easy one.

Three ideas carry the design:

  * **Backups come in sets, not files.** frappe writes a database dump, a public
    files tar, a private files tar and a site_config snapshot, all sharing one
    timestamp prefix. Asking someone to find and match four paths by hand is how
    you restore the database from Tuesday over the files from Friday. They are
    grouped back into sets here and picked as one thing.

  * **The database root password never reaches the log.** It has to be passed to
    `bench restore`, and `request.command` is stored and shown in the interface,
    so the stored copy is redacted. This app exists because a server was
    compromised; leaving a root password in a log it displays would be absurd.

  * **Take a backup before overwriting.** `bench restore` does not, and the
    moment you want one is the moment it is already gone.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime

#: frappe names every backup `<YYYYMMDD>_<HHMMSS>-<site>-<kind>`, with dots in
#: the site name replaced by underscores. That shared prefix is what lets the
#: four files be regrouped into the set they were written as.
BACKUP_NAME = re.compile(
	r"^(?P<stamp>\d{8}_\d{6})-(?P<site>.+?)-(?P<kind>database\.sql\.gz|files\.tar|private-files\.tar|site_config_backup\.json)$"
)

KIND_DATABASE = "database.sql.gz"
KIND_PUBLIC = "files.tar"
KIND_PRIVATE = "private-files.tar"
KIND_CONFIG = "site_config_backup.json"

#: Anything that looks like a secret is replaced before the command is stored.
SECRET_FLAGS = ("--db-root-password", "--encryption-key", "--admin-password")

REDACTED = "********"


class RestoreRefused(Exception):
	"""Raised when a restore cannot be built or should not be attempted."""


@dataclass(frozen=True)
class BackupSet:
	"""One backup, as the four files frappe wrote together."""

	key: str
	site_slug: str
	taken_at: str
	database: str
	public_files: str | None = None
	private_files: str | None = None
	site_config: str | None = None
	size: int = 0
	encrypted: bool = False
	source: str = "site"

	@property
	def has_files(self) -> bool:
		return bool(self.public_files or self.private_files)


def _human_size(count: int) -> str:
	value = float(count)
	for unit in ("B", "KB", "MB", "GB"):
		if value < 1024 or unit == "GB":
			return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
		value /= 1024
	return f"{value:.1f} GB"


def _is_encrypted(path: str) -> bool:
	"""True when the dump is not a plain gzip stream.

	frappe encrypts backups when the site asks it to, and an encrypted dump
	restores only with its key. Reading the two magic bytes is enough to tell,
	and it means the dialog can ask for the key instead of letting the restore
	fail after dropping the database.
	"""
	try:
		with open(path, "rb") as handle:
			return handle.read(2) != b"\x1f\x8b"
	except OSError:
		return False


def _stamp_to_text(stamp: str) -> str:
	try:
		return datetime.strptime(stamp, "%Y%m%d_%H%M%S").strftime("%d %b %Y, %H:%M")
	except ValueError:
		return stamp


def backup_directories(bench_path: str, site: str) -> list[tuple[str, str]]:
	"""Where to look for backups, and what to call each place.

	The site's own backup directory is where scheduled backups land. The bench
	root is the drop zone — copying a backup from another server into the bench
	directory and restoring it from there is the whole reason this exists.
	"""
	return [
		(os.path.join(bench_path, "sites", site, "private", "backups"), "site"),
		(os.path.join(bench_path, "backups"), "bench"),
		(bench_path, "bench"),
	]


def list_backups(bench_path: str, site: str) -> list[BackupSet]:
	"""Every restorable backup visible to this bench, newest first.

	Sets from any site are returned, not just this one — restoring another
	site's backup onto this site is a legitimate thing to do (staging from
	production), and silently hiding those files would look like a bug. The
	mismatch is reported instead, in `describe_mismatch`.
	"""
	grouped: dict[tuple[str, str], dict] = {}

	for directory, source in backup_directories(bench_path, site):
		if not os.path.isdir(directory):
			continue
		try:
			names = os.listdir(directory)
		except OSError:
			continue

		for name in names:
			match = BACKUP_NAME.match(name)
			if not match:
				continue
			path = os.path.join(directory, name)
			if not os.path.isfile(path):
				continue

			key = (match["stamp"], match["site"])
			entry = grouped.setdefault(
				key, {"files": {}, "size": 0, "source": source, "directory": directory}
			)
			# A set is keyed by stamp and site, so the same backup copied into
			# two places collapses into one entry rather than appearing twice.
			if match["kind"] not in entry["files"]:
				entry["files"][match["kind"]] = path
				entry["size"] += os.path.getsize(path)

	sets: list[BackupSet] = []
	for (stamp, site_slug), entry in grouped.items():
		database = entry["files"].get(KIND_DATABASE)
		if not database:
			# Without a dump there is nothing to restore; a stray files tar is
			# not a backup.
			continue
		sets.append(
			BackupSet(
				key=f"{stamp}-{site_slug}",
				site_slug=site_slug,
				taken_at=_stamp_to_text(stamp),
				database=database,
				public_files=entry["files"].get(KIND_PUBLIC),
				private_files=entry["files"].get(KIND_PRIVATE),
				site_config=entry["files"].get(KIND_CONFIG),
				size=entry["size"],
				encrypted=_is_encrypted(database),
				source=entry["source"],
			)
		)

	sets.sort(key=lambda s: s.key, reverse=True)
	return sets


def as_dict(backup: BackupSet, site: str) -> dict:
	"""One backup shaped for the dialog, including why it might be wrong."""
	return {
		**backup.__dict__,
		"has_files": backup.has_files,
		"size_text": _human_size(backup.size),
		"mismatch": describe_mismatch(backup, site),
	}


def site_slug(site: str) -> str:
	"""frappe's own transformation: dots in a site name become underscores."""
	return site.replace(".", "_")


def describe_mismatch(backup: BackupSet, site: str) -> str:
	"""Warn when a backup came from a different site.

	Restoring across sites is allowed and sometimes intended, so this is a
	sentence and not a refusal — but it is the mistake most worth catching,
	because it looks completely normal until the data is already replaced.
	"""
	if backup.site_slug == site_slug(site):
		return ""
	return (
		f"This backup is from {backup.site_slug.replace('_', '.')}, not {site}. "
		"Restoring it will replace this site's data with that site's data."
	)


def find(bench_path: str, site: str, key: str) -> BackupSet:
	backup = next((b for b in list_backups(bench_path, site) if b.key == key), None)
	if not backup:
		raise RestoreRefused(
			f"Backup {key!r} is no longer on disk. It may have been rotated away — reopen the "
			"dialog to see what is there now."
		)
	return backup


def build_backup_argv(bench_exe: str, site: str, with_files: bool) -> list[str]:
	"""The safety net taken immediately before the restore."""
	argv = [bench_exe, "--site", site, "backup"]
	if with_files:
		argv.append("--with-files")
	return argv


def build_argv(
	bench_exe: str,
	site: str,
	backup: BackupSet,
	db_root_password: str,
	db_root_username: str | None = None,
	encryption_key: str | None = None,
	with_public: bool = False,
	with_private: bool = False,
) -> list[str]:
	"""The exact `bench restore` argv.

	The root password goes on the command line because that is the only way
	`bench restore` accepts one — without it frappe calls `getpass()`, which in
	a worker with no terminal fails with an error about stdin rather than
	anything that explains itself. `redact` exists because of this.
	"""
	if not db_root_password:
		raise RestoreRefused(
			"The database root password is required. Without it bench asks for it on a terminal "
			"that a background job does not have."
		)
	if backup.encrypted and not encryption_key:
		raise RestoreRefused(
			"This backup is encrypted and cannot be restored without its encryption key. "
			"It is in the site's `encryption_key` setting on the server it was taken from."
		)

	argv = [bench_exe, "--site", site, "restore", backup.database]
	argv += ["--db-root-password", db_root_password]
	if db_root_username:
		argv += ["--db-root-username", db_root_username]
	if encryption_key:
		argv += ["--encryption-key", encryption_key]
	if with_public and backup.public_files:
		argv += ["--with-public-files", backup.public_files]
	if with_private and backup.private_files:
		argv += ["--with-private-files", backup.private_files]
	return argv


def redact(argv: list[str]) -> list[str]:
	"""A copy of the argv safe to store, log and display.

	The value after each secret flag is replaced, not removed, so the stored
	command is still a faithful record of what ran.
	"""
	out = list(argv)
	for index, token in enumerate(out):
		if token in SECRET_FLAGS and index + 1 < len(out):
			out[index + 1] = REDACTED
	return out
