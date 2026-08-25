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
import shutil
from dataclasses import dataclass
from datetime import datetime

#: frappe names every backup `<YYYYMMDD>_<HHMMSS>-<site>-<kind>`, with dots in
#: the site name replaced by underscores. That shared prefix is what lets the
#: four files be regrouped into the set they were written as.
#: `-enc` is frappe's own marker for an encrypted backup, and `-partial` for a
#: partial one. Without them in the pattern an encrypted backup set does not
#: match at all, so it never appears in the picker — the operator is simply told
#: there are no backups.
BACKUP_NAME = re.compile(
	r"^(?P<stamp>\d{8}_\d{6})-(?P<site>.+?)(?P<partial>-partial)?-"
	r"(?P<kind>database|files|private-files|site_config_backup)"
	r"(?P<enc>-enc)?"
	r"(?P<ext>\.sql\.gz|\.tar\.gz|\.tgz|\.tar|\.json)$"
)

KIND_DATABASE = "database"
KIND_PUBLIC = "files"
KIND_PRIVATE = "private-files"
KIND_CONFIG = "site_config_backup"

#: `gpg -c` output begins with an OpenPGP symmetric-key packet. Frappe encrypts
#: backups with gpg, not with Fernet as its imports suggest — verified against
#: real gpg output, which starts 8c 0d.
GPG_MAGIC = (b"\x8c", b"\x85", b"\xc3")

GZIP_MAGIC = b"\x1f\x8b"

#: What the start of an uncompressed SQL dump looks like.
SQL_PREFIXES = (b"--", b"/*", b"CREATE", b"SET ", b"DROP ", b"INSERT", b"USE ", b"\n--")

#: Anything that looks like a secret is replaced before the command is stored.
SECRET_FLAGS = ("--db-root-password", "--encryption-key", "--admin-password")

REDACTED = "********"


#: What a file looks like it is, from its name alone. Used to pre-sort the
#: picker; never used to decide what a file IS, because a backup copied in from
#: another system can be called anything.
KIND_GUESSES = (
	# `-enc` is optional throughout: frappe appends it to encrypted backups, and
	# a guess that ignores it files every encrypted file under the wrong kind.
	("private", re.compile(r"private[-_]?files(-enc)?\.(tar|tgz|tar\.gz)$", re.I)),
	("public", re.compile(r"(^|[-_])files(-enc)?\.(tar|tgz|tar\.gz)$", re.I)),
	("database", re.compile(r"(-enc)?\.sql(\.gz)?$", re.I)),
	("public", re.compile(r"\.(tar|tgz|tar\.gz)$", re.I)),
)

#: Extensions worth offering at all. Anything else in the bench directory is
#: noise in a picker whose job is to be short.
RESTORABLE = (".sql", ".sql.gz", ".tar", ".tar.gz", ".tgz")

#: Included so an encrypted set is offered rather than silently absent.

#: How deep to walk looking for candidates. The bench root holds apps/, env/ and
#: sites/, which together are tens of thousands of files; a backup someone
#: copied in is at the top or one level down, never buried.
SCAN_DEPTH = 2

#: Directories that can only cost time. env/ and node_modules/ are enormous and
#: contain nothing restorable.
SKIP_DIRS = {"apps", "env", "node_modules", ".git", "logs", "config", "archived", "__pycache__"}


class RestoreRefused(Exception):
	"""Raised when a restore cannot be built or should not be attempted."""


@dataclass(frozen=True)
class FileCandidate:
	"""One file on disk that could take part in a restore."""

	path: str
	name: str
	directory: str
	kind: str
	size: int
	size_text: str
	modified: str
	#: True when this file belongs to a backup set frappe wrote, which is the
	#: signal that picking its siblings by hand is the wrong move.
	in_set: bool = False
	#: Whether restoring it needs a key. Read here so the dialog can ask for
	#: one; without it the hand-picked path silently offered encrypted dumps
	#: it could never restore.
	encrypted: bool = False


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
	"""True when this dump needs a key to restore.

	Three cases, not two. "Anything that is not gzip is encrypted" was wrong in
	the direction that matters: a plain uncompressed `mysqldump` output — which
	is exactly what gets copied in from another server, the case the whole
	hand-picked path exists for — was reported as encrypted and became
	impossible to restore, because the only way past the check was to invent an
	encryption key.

	frappe's own marker is checked first: it names encrypted files `-enc`, which
	is more reliable than any magic byte because it survives the file being
	recompressed or renamed by whatever copied it over.
	"""
	if "-enc." in os.path.basename(path):
		return True

	try:
		with open(path, "rb") as handle:
			head = handle.read(8)
	except OSError:
		return False

	if head.startswith(GZIP_MAGIC):
		return False
	if head[:1] in GPG_MAGIC:
		return True
	# Readable SQL: a plain dump, not an encrypted one.
	if any(head.upper().startswith(prefix.upper()) for prefix in SQL_PREFIXES):
		return False
	# Unrecognised. Say encrypted rather than let bench drop the database and
	# then fail to load anything into it.
	return True


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


# ----------------------------------------------------------------------
# Picking files by hand
# ----------------------------------------------------------------------


def classify(name: str) -> str:
	"""What a filename suggests the file is. A guess, and labelled as one."""
	for kind, pattern in KIND_GUESSES:
		if pattern.search(name):
			return kind
	return "unknown"


def _is_restorable(name: str) -> bool:
	lowered = name.lower()
	return any(lowered.endswith(ext) for ext in RESTORABLE)


def is_inside(root: str, path: str) -> bool:
	"""True when `path` really is under `root`, symlinks resolved.

	Restore paths arrive from a browser, and `bench restore` will happily read
	/etc/shadow if asked. Comparing resolved paths — rather than the strings —
	is what stops `../../..` and a symlink planted in the bench directory from
	reaching outside it.
	"""
	try:
		root_real = os.path.realpath(root)
		path_real = os.path.realpath(path)
	except OSError:
		return False
	return os.path.commonpath([root_real, path_real]) == root_real


def list_files(bench_path: str, site: str) -> list[FileCandidate]:
	"""Every file in the bench that could be part of a restore.

	Bounded on purpose. A bench root contains apps/ and env/ — hundreds of
	thousands of files — and a backup someone copied in is at the top level or
	one directory down. Walking the whole tree would take seconds and return
	nothing extra.
	"""
	in_sets = {
		path
		for backup in list_backups(bench_path, site)
		for path in (backup.database, backup.public_files, backup.private_files)
		if path
	}

	seen: set[str] = set()
	found: list[FileCandidate] = []

	roots = [directory for directory, _ in backup_directories(bench_path, site)]
	for root in roots:
		if not os.path.isdir(root):
			continue
		base_depth = root.rstrip(os.sep).count(os.sep)
		for current, dirs, names in os.walk(root):
			if current.rstrip(os.sep).count(os.sep) - base_depth >= SCAN_DEPTH:
				dirs[:] = []
			dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

			for name in names:
				if not _is_restorable(name):
					continue
				path = os.path.join(current, name)
				real = os.path.realpath(path)
				if real in seen or not os.path.isfile(path):
					continue
				seen.add(real)
				try:
					stat = os.stat(path)
				except OSError:
					continue
				found.append(
					FileCandidate(
						path=path,
						name=name,
						directory=os.path.dirname(path),
						kind=classify(name),
						size=stat.st_size,
						size_text=_human_size(stat.st_size),
						modified=datetime.fromtimestamp(stat.st_mtime).strftime("%d %b %Y, %H:%M"),
						in_set=path in in_sets,
						# Only meaningful for a dump; a tar is never encrypted
						# separately by frappe.
						encrypted=classify(name) == "database" and _is_encrypted(path),
					)
				)

	found.sort(key=lambda f: f.name, reverse=True)
	return found


def resolve_chosen(
	bench_path: str,
	site: str,
	database: str,
	public: str | None = None,
	private: str | None = None,
) -> BackupSet:
	"""Turn three hand-picked paths into the same BackupSet the rest expects.

	Everything downstream — the argv builder, the pre-flights, the job — works
	on a BackupSet, so choosing files by hand converges here rather than growing
	a second code path that could drift from the first.
	"""
	if not database:
		raise RestoreRefused("A database dump is required. Files alone cannot restore a site.")

	chosen = {"database": database, "public files": public, "private files": private}
	for label, path in chosen.items():
		if not path:
			continue
		if not is_inside(bench_path, path):
			raise RestoreRefused(
				f"The {label} must be a file inside {bench_path}. Copy the backup into the bench "
				"directory first — restoring from anywhere on the server is not allowed."
			)
		if not os.path.isfile(path):
			raise RestoreRefused(f"{path} is not a file.")

	stamp = ""
	match = BACKUP_NAME.match(os.path.basename(database))
	if match:
		stamp = match["stamp"]

	size = sum(os.path.getsize(p) for p in chosen.values() if p)
	return BackupSet(
		key=f"chosen:{os.path.basename(database)}",
		# Named after the file, so a mismatch warning still fires when someone
		# hand-picks another site's dump.
		site_slug=match["site"] if match else site_slug(site),
		taken_at=_stamp_to_text(stamp) if stamp else _modified_text(database),
		database=database,
		public_files=public or None,
		private_files=private or None,
		size=size,
		encrypted=_is_encrypted(database),
		source="chosen",
	)


def _modified_text(path: str) -> str:
	try:
		return datetime.fromtimestamp(os.path.getmtime(path)).strftime("%d %b %Y, %H:%M")
	except OSError:
		return "unknown"


# ----------------------------------------------------------------------
# Disk space
# ----------------------------------------------------------------------

#: A gzipped SQL dump expands hard, and MariaDB then writes binlogs of roughly
#: the same volume while loading it. This is press's own multiplier
#: (`8 * db_file_size * 2` in press/press/doctype/site/site.py) and it is the
#: number Frappe Cloud restores against in production.
DB_EXPANSION = 16

#: Below this, refuse to guess. A disk with almost nothing left will fail for
#: reasons that have nothing to do with the estimate.
FLOOR_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class SpaceEstimate:
	"""Whether this restore will fit, and the numbers behind the answer."""

	required: int
	free: int
	total: int
	mountpoint: str
	enough: bool
	detail: str

	@property
	def required_text(self) -> str:
		return _human_size(self.required)

	@property
	def free_text(self) -> str:
		return _human_size(self.free)


def estimate_space(bench_path: str, backup: BackupSet) -> SpaceEstimate:
	"""Estimate whether there is room to restore this backup.

	An estimate and labelled as one — compression ratios vary enormously. It is
	worth making anyway: running out of disk half way through a restore leaves
	a partly-loaded database on a full disk, which is materially worse than not
	starting.
	"""
	database = _size_of(backup.database)
	files = _size_of(backup.public_files) + _size_of(backup.private_files)
	required = database * DB_EXPANSION + files

	try:
		usage = shutil.disk_usage(bench_path)
	except OSError as exc:
		return SpaceEstimate(required, 0, 0, bench_path, True, f"Could not read disk usage: {exc}")

	enough = usage.free >= required and usage.free >= FLOOR_BYTES
	if enough:
		detail = (
			f"About {_human_size(required)} needed, {_human_size(usage.free)} free. "
			f"The dump is expected to expand about {DB_EXPANSION}x once loaded."
		)
	else:
		short = max(required - usage.free, 0)
		detail = (
			f"About {_human_size(required)} needed but only {_human_size(usage.free)} is free — "
			f"roughly {_human_size(short)} short. A restore that fills the disk leaves a "
			"half-loaded database behind. This is an estimate: a dump expands about "
			f"{DB_EXPANSION}x with its binlogs, and yours may be smaller."
		)

	return SpaceEstimate(required, usage.free, usage.total, bench_path, enough, detail)


def _size_of(path: str | None) -> int:
	if not path:
		return 0
	try:
		return os.path.getsize(path)
	except OSError:
		return 0


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
