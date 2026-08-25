# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What is on the disk that should not be, and what changed that should not have.

This is deliberately NOT a rootkit detector, and not a general file-integrity
monitor either. Hashing every file on the system produces a number nobody
reads and a nightly diff nobody finishes. It looks at four narrow things, each
chosen because it is both cheap to check and hard for an intruder to avoid:

  setuid and setgid binaries   the classic way a foothold becomes root, and a
                               list short enough (21 files here) that ANY
                               addition is worth a person's attention;
  package integrity            dpkg knows the checksum of every file it
                               installed, so a replaced system binary is a
                               question already answered -- for free, by a
                               database that is already on the box;
  binaries in temp directories  /tmp, /var/tmp and /dev/shm are where droppers
                               stage, because they are writable by everyone
                               and often survive nothing;
  world-writable system files  anything in /etc or the binary directories that
                               anyone can rewrite is a foothold waiting to be
                               used, whether or not it has been yet.

MEASURED ON REAL HARDWARE, because each of these is worthless if it is noisy:

  * `dpkg --verify` returns 341 lines here, and 337 of them are "missing"
    files under dist-packages that pip removed. Of the four remaining, two are
    checksum mismatches on CONFFILES -- nginx.conf and mariadb.cnf -- which an
    administrator is supposed to edit. That is the whole rule: a modified
    conffile is Tuesday, a modified non-conffile is a replaced binary.
  * /tmp holds 734 executable files on this box. Filtering to actual ELF
    binaries leaves 2, both explainable. "Executable in /tmp" would have been
    unusable; "ELF binary in /tmp" is a sentence worth reading.

Frappe-free on purpose, like `persistence.py` and `ssh/parser.py`: it collects
and describes, it does not decide and it does not store. `filesystem_rules.py`
judges, `watch.py` records.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from dataclasses import dataclass, field

from server.security.persistence import Surface, _hash, owning_packages

KIND_SETUID = "setuid"
KIND_PACKAGE = "package-integrity"
KIND_TEMP_BINARY = "temp-binary"
KIND_WORLD_WRITABLE = "world-writable"

#: Where a setuid binary could legitimately live. Deliberately not "/", which
#: would walk every bench, every node_modules and every site's files on a box
#: whose whole job is holding those.
SETUID_ROOTS = ("/usr", "/bin", "/sbin", "/opt", "/srv")

#: Writable by everyone, cleared inconsistently, and on the default PATH of
#: nothing -- which is exactly why a dropper lands here first.
TEMP_DIRECTORIES = ("/tmp", "/var/tmp", "/dev/shm")

#: Where a world-writable file is always wrong. /tmp is 1777 by design and is
#: not in this list; the point is files ANYONE can rewrite that something
#: privileged will read or run.
WRITABLE_ROOTS = ("/etc", "/usr/bin", "/usr/sbin", "/usr/local", "/bin", "/sbin")

#: Don't descend into these while sweeping. Package managers and language
#: runtimes ship enormous trees that are already covered by dpkg, and a bench
#: holds hundreds of thousands of files that are the app's own business.
SKIP_DIRECTORIES = frozenset(
	{
		"node_modules",
		"__pycache__",
		".git",
		".cache",
		"site-packages",
		"dist-packages",
	}
)

#: How deep a temp sweep goes. Set from a real miss rather than a guess: the
#: first version capped at 4 and skipped two genuine ELF binaries sitting at
#: depth 6 in a cloned repository under /tmp. The cap is a backstop against a
#: pathological tree, not a filter -- the sweep itself costs a fifth of a
#: second on 734 files, so there is nothing to buy by cutting it close.
TEMP_MAX_DEPTH = 8

_ELF_MAGIC = b"\x7fELF"

#: `dpkg --verify` in rpm format: nine flag characters, an optional file-type
#: column, then the path. Position 3 is the checksum -- the only one dpkg
#: actually populates today. A `c` in the type column means conffile.
_VERIFY_LINE = re.compile(r"^(?P<flags>[?.\w]{9})\s+(?:(?P<type>\w)\s+)?(?P<path>/.*)$")


@dataclass(frozen=True)
class Item:
	"""One thing found on disk that the rules may care about."""

	kind: str
	#: Unique within its kind. The path, for everything here.
	identifier: str
	content_hash: str = ""
	path: str = ""
	package: str = ""
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
class VerifyRecord:
	"""One line of `dpkg --verify` output."""

	path: str
	flags: str
	#: "c" for a conffile, "" for anything else. The whole rule turns on this.
	file_type: str = ""

	@property
	def missing(self) -> bool:
		return self.flags.strip().lower() == "missing"

	@property
	def checksum_differs(self) -> bool:
		"""Position 3 of the flag field is the md5 check."""
		return len(self.flags) >= 3 and self.flags[2] == "5"

	@property
	def is_conffile(self) -> bool:
		return self.file_type == "c"


@dataclass(frozen=True)
class Snapshot:
	items: tuple[Item, ...]
	surfaces: tuple[Surface, ...]


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _is_elf(path: str) -> bool:
	"""Four bytes, not `file(1)`.

	Spawning a process per candidate would cost more than the sweep itself,
	and the magic number is the same thing `file` would read.
	"""
	try:
		with open(path, "rb") as handle:
			return handle.read(4) == _ELF_MAGIC
	except OSError:
		return False


def _hash_file(path: str, limit: int = 32 * 1024 * 1024) -> str:
	"""Hash a file, refusing anything implausibly large.

	The limit is not about memory -- it is read in chunks -- but about time. A
	setuid binary is measured in kilobytes; something enormous claiming to be
	one is itself worth reporting, and hashing it would stall the scan.
	"""
	import hashlib

	digest = hashlib.sha256()
	try:
		size = os.path.getsize(path)
		if size > limit:
			return ""
		with open(path, "rb") as handle:
			for chunk in iter(lambda: handle.read(1024 * 1024), b""):
				digest.update(chunk)
	except OSError:
		return ""
	return digest.hexdigest()


def _owner(info: os.stat_result) -> str:
	"""Resolve uid:gid to names, falling back to the numbers.

	A uid with no passwd entry is not an error to swallow -- an account
	deleted while its files remain is itself a thing worth seeing in a
	finding -- so the number is kept rather than dropped.
	"""
	import grp
	import pwd

	try:
		user = pwd.getpwuid(info.st_uid).pw_name
	except (KeyError, OSError):
		user = str(info.st_uid)
	try:
		group = grp.getgrgid(info.st_gid).gr_name
	except (KeyError, OSError):
		group = str(info.st_gid)
	return f"{user}:{group}"


def _distinct_roots(roots: tuple[str, ...]) -> list[tuple[str, str]]:
	"""Resolve roots and drop the ones that are the same place twice.

	THE MERGED-/usr TRAP, for the third time in this app. On Ubuntu 24.04
	`/bin`, `/sbin` and `/lib` are symlinks into `/usr`, so walking
	("/usr", "/bin", "/sbin") walks /usr/bin and /usr/sbin twice each. The
	first version of this module reported 37 setuid binaries where `find`
	reports 21 -- and the 16 phantoms were not an over-count, they were the
	same files listed under two spellings, each of which would have had to be
	baselined separately and would have alerted separately forever after.

	Returns (requested, resolved) pairs so a surface can still be recorded
	against the path that was ASKED for. Coverage answers "did you look in
	/sbin", and "it is the same place as /usr/sbin" is a real answer to that.
	"""
	kept: list[str] = []
	pairs = []
	for root in roots:
		resolved = os.path.realpath(root)
		# Nested, not just identical: /bin resolves to /usr/bin, which is
		# INSIDE /usr and would therefore be swept a second time. The results
		# collapse in a dict either way, so this is about the seconds, not the
		# count -- it is most of the difference between a 3.5s sweep and a 1.8s
		# one, every quarter of an hour, forever.
		if any(resolved == done or resolved.startswith(done + "/") for done in kept):
			pairs.append((root, ""))
			continue
		kept.append(resolved)
		pairs.append((root, resolved))
	return pairs


def _walk(root: str, max_depth: int | None = None):
	"""Yield (path, stat) for regular files under `root`, one filesystem only.

	Hand-rolled rather than `os.walk` for three reasons that all matter here:
	symlinks are never followed (a symlink into /proc turns a sweep into an
	eternity), other filesystems are never crossed (a bind-mounted site's
	files are not this scan's business), and directories are pruned by name
	before they are entered rather than after.
	"""
	try:
		root_device = os.stat(root).st_dev
	except OSError:
		return

	stack = [(root, 0)]
	while stack:
		current, depth = stack.pop()
		try:
			entries = list(os.scandir(current))
		except OSError:
			continue

		for entry in entries:
			try:
				if entry.is_dir(follow_symlinks=False):
					if entry.name in SKIP_DIRECTORIES:
						continue
					if max_depth is not None and depth >= max_depth:
						continue
					if entry.stat(follow_symlinks=False).st_dev != root_device:
						continue
					stack.append((entry.path, depth + 1))
				elif entry.is_file(follow_symlinks=False):
					yield entry.path, entry.stat(follow_symlinks=False)
			except OSError:
				continue


# ----------------------------------------------------------------------
# Collectors
# ----------------------------------------------------------------------


def collect_setuid(roots: tuple[str, ...] = SETUID_ROOTS) -> tuple[list[Item], list[Surface]]:
	"""Every setuid and setgid file, hashed, with its owning package.

	Hashing is affordable precisely because the list is short. It is what
	turns "sudo is still here" into "sudo is still the sudo dpkg installed",
	which is the version of the question worth asking.
	"""
	items: list[Item] = []
	surfaces: list[Surface] = []
	found: dict[str, os.stat_result] = {}

	for requested, root in _distinct_roots(roots):
		if not root:
			surfaces.append(Surface(KIND_SETUID, requested, True, "same directory as another root", 0))
			continue
		if not os.path.isdir(root):
			# Not an error: /srv and /opt are absent on plenty of hosts.
			# Recorded as readable-with-nothing-in-it, not as a gap.
			surfaces.append(Surface(KIND_SETUID, requested, True, "not present", 0))
			continue

		before = len(found)
		try:
			for path, info in _walk(root):
				if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
					found[path] = info
		except OSError as exc:
			surfaces.append(Surface(KIND_SETUID, requested, False, str(exc), 0))
			continue
		surfaces.append(Surface(KIND_SETUID, requested, True, "", len(found) - before))

	packages = owning_packages(sorted(found))
	for path, info in sorted(found.items()):
		items.append(
			Item(
				kind=KIND_SETUID,
				identifier=path,
				path=path,
				content_hash=_hash_file(path),
				package=packages.get(path, ""),
				detail={
					"mode": stat.filemode(info.st_mode),
					"owner": _owner(info),
					"size": info.st_size,
					"setuid": bool(info.st_mode & stat.S_ISUID),
					"setgid": bool(info.st_mode & stat.S_ISGID),
				},
			)
		)
	return items, surfaces


def parse_dpkg_verify(text: str) -> list[VerifyRecord]:
	"""Parse `dpkg --verify --verify-format rpm` output.

	Pure, so the format can be tested without dpkg and without root -- which
	matters because the man page says the default output format "might change
	in the future". That is why the collector pins `--verify-format rpm`
	explicitly rather than trusting the default it happens to get today.
	"""
	records = []
	for line in text.splitlines():
		line = line.rstrip()
		if not line:
			continue

		# "missing" lines are a different shape from flag lines.
		if line.startswith("missing"):
			path = line[len("missing") :].strip()
			# A missing conffile is still marked, and still not interesting.
			file_type = ""
			if path.startswith("c "):
				file_type, path = "c", path[2:].strip()
			if path.startswith("/"):
				records.append(VerifyRecord(path=path, flags="missing", file_type=file_type))
			continue

		match = _VERIFY_LINE.match(line)
		if match:
			records.append(
				VerifyRecord(
					path=match.group("path").strip(),
					flags=match.group("flags"),
					file_type=match.group("type") or "",
				)
			)
	return records


def collect_package_integrity() -> tuple[list[Item], list[Surface]]:
	"""Ask dpkg whether the files it installed are still the files it installed.

	Only records what is actually interesting. The 337 "missing" lines this
	returns on a normal box are dropped here rather than in the rules,
	because carrying them into the database would mean storing three hundred
	rows a scan to describe pip having tidied up after itself.
	"""
	try:
		result = subprocess.run(  # noqa: S603
			["dpkg", "--verify", "--verify-format", "rpm"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=600,
			check=False,
		)
	except FileNotFoundError:
		return [], [Surface(KIND_PACKAGE, "dpkg", False, "dpkg is not installed", 0)]
	except (OSError, subprocess.SubprocessError) as exc:
		return [], [Surface(KIND_PACKAGE, "dpkg", False, str(exc), 0)]

	records = parse_dpkg_verify(result.stdout)
	items = [
		Item(
			kind=KIND_PACKAGE,
			identifier=record.path,
			path=record.path,
			content_hash=_hash_file(record.path) if not record.is_conffile else "",
			detail={
				"flags": record.flags,
				"conffile": record.is_conffile,
			},
		)
		for record in records
		if record.checksum_differs
	]
	return items, [Surface(KIND_PACKAGE, "dpkg", True, "", len(items))]


def collect_temp_binaries(
	directories: tuple[str, ...] = TEMP_DIRECTORIES,
) -> tuple[list[Item], list[Surface]]:
	"""ELF binaries staged in world-writable temp directories.

	The ELF filter is the entire reason this rule is usable. Without it this
	box reports 734 files; with it, 2 -- and both are explainable. A shell
	script in /tmp is every build system ever written; a compiled binary in
	/tmp is somebody's choice.
	"""
	items: list[Item] = []
	surfaces: list[Surface] = []

	for directory in directories:
		if not os.path.isdir(directory):
			surfaces.append(Surface(KIND_TEMP_BINARY, directory, True, "not present", 0))
			continue

		count = 0
		try:
			for path, info in _walk(directory, max_depth=TEMP_MAX_DEPTH):
				if not info.st_mode & 0o111:
					continue
				if not _is_elf(path):
					continue
				count += 1
				items.append(
					Item(
						kind=KIND_TEMP_BINARY,
						identifier=path,
						path=path,
						content_hash=_hash_file(path),
						detail={
							"mode": stat.filemode(info.st_mode),
							"owner": _owner(info),
							"size": info.st_size,
							"setuid": bool(info.st_mode & stat.S_ISUID),
						},
					)
				)
		except OSError as exc:
			surfaces.append(Surface(KIND_TEMP_BINARY, directory, False, str(exc), 0))
			continue
		surfaces.append(Surface(KIND_TEMP_BINARY, directory, True, "", count))

	return items, surfaces


def collect_world_writable(
	roots: tuple[str, ...] = WRITABLE_ROOTS,
) -> tuple[list[Item], list[Surface]]:
	"""Files anyone can rewrite, in places only root should be writing.

	Zero of these on a healthy box, which makes it the cheapest signal in this
	module: there is no baseline to learn and no noise to tune out. A single
	result is worth reading.
	"""
	items: list[Item] = []
	surfaces: list[Surface] = []

	for requested, root in _distinct_roots(roots):
		if not root:
			surfaces.append(Surface(KIND_WORLD_WRITABLE, requested, True, "same directory as another root", 0))
			continue
		if not os.path.isdir(root):
			# Not an error: /srv and /opt are absent on plenty of hosts.
			# Recorded as readable-with-nothing-in-it, not as a gap.
			surfaces.append(Surface(KIND_WORLD_WRITABLE, requested, True, "not present", 0))
			continue

		count = 0
		try:
			for path, info in _walk(root):
				if not info.st_mode & stat.S_IWOTH:
					continue
				count += 1
				items.append(
					Item(
						kind=KIND_WORLD_WRITABLE,
						identifier=path,
						path=path,
						detail={
							"mode": stat.filemode(info.st_mode),
							"owner": _owner(info),
							"executable": bool(info.st_mode & 0o111),
						},
					)
				)
		except OSError as exc:
			surfaces.append(Surface(KIND_WORLD_WRITABLE, requested, False, str(exc), 0))
			continue
		surfaces.append(Surface(KIND_WORLD_WRITABLE, requested, True, "", count))

	return items, surfaces


#: Cheap enough to run on the ordinary detector schedule. Measured: 1.8s for
#: the setuid sweep, 2.5s for the temp directories, 0.1s for world-writable.
FAST_COLLECTORS = (
	collect_setuid,
	collect_temp_binaries,
	collect_world_writable,
)

#: Run once a day instead, because `dpkg --verify` re-hashes every file every
#: installed package owns: 40 seconds of solid I/O on this box, against 4.4
#: for everything else put together. Daily is also the honest cadence for what
#: it detects -- a replaced system binary does not revert itself while you are
#: not looking, so catching it within a day loses nothing, and hammering the
#: disk every quarter hour to hear "still fine" costs a real server real
#: throughput. Debian's own debsums cron runs weekly.
DEEP_COLLECTORS = (collect_package_integrity,)

COLLECTORS = FAST_COLLECTORS + DEEP_COLLECTORS


def collect(deep: bool = False) -> Snapshot:
	"""Everything, with one collector's failure never costing the others.

	A sweep that raises halfway leaves a snapshot missing surfaces it never
	recorded, which reads downstream as "nothing there" -- the confident empty
	answer this whole design exists to avoid.

	`deep` adds package verification. Callers that pass False get no
	package-integrity SURFACE either, which is deliberate: a surface saying
	"dpkg: 0 findings" would be a claim that the check ran.
	"""
	items: list[Item] = []
	surfaces: list[Surface] = []
	for collector in FAST_COLLECTORS + (DEEP_COLLECTORS if deep else ()):
		try:
			found, looked = collector()
		except Exception as exc:  # noqa: BLE001
			surfaces.append(Surface(collector.__name__, "", False, f"{type(exc).__name__}: {exc}", 0))
			continue
		items.extend(found)
		surfaces.extend(looked)
	return Snapshot(items=tuple(items), surfaces=tuple(surfaces))
