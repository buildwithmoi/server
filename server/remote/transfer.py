# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Deciding what to pull from another server, and where it lands.

The moving itself is `RemoteServer.download`. This is the part around it: which
files a set actually has, what to call them here, and whether there is room —
all answerable before a single byte crosses, which matters when the answer is
"no" and the alternative is finding out forty minutes in.

WHERE THE FILES GO, and why it is not a temporary directory. They land in
`<bench>/backups/`, the same place `upload_backup_chunk` puts a file dropped in
from a laptop. That is deliberate: from there they are an ordinary set that
`restore.list_files` finds and `resolve_chosen` can build, so a pulled backup
takes exactly the same restore path as a hand-picked one and there is no second
notion of what a restorable file is. It also means a transfer interrupted after
the download but before the restore is not wasted — the files are sitting where
the picker will offer them.

Frappe-free, so the naming and the space arithmetic test without a site.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass

#: The parts worth moving, in the order they are pulled. Database first: it is
#: the one a restore cannot proceed without, so a transfer that is going to
#: fail should fail before spending time on the files.
PARTS = ("database", "public", "private", "config")

#: Room to leave free after the pull. Filling a disk to the last byte is how a
#: restore fails at the point it has already dropped the database.
HEADROOM = 2 * 1024**3


class TransferRefused(Exception):
	"""The pull will not be attempted, with a reason worth showing."""


@dataclass(frozen=True)
class Wanted:
	"""One file to pull."""

	part: str
	filename: str
	size: int
	destination: str

	@property
	def size_text(self) -> str:
		value = float(self.size)
		for unit in ("B", "KB", "MB", "GB"):
			if value < 1024 or unit == "GB":
				return f"{value:.0f} {unit}" if unit in ("B", "KB") else f"{value:.1f} {unit}"
			value /= 1024
		return f"{value:.1f} GB"


def plan(backup: dict, directory: str, want_public: bool = True, want_private: bool = True) -> list[Wanted]:
	"""Which files to pull, and what to call them here.

	The remote's own filenames are kept. They already carry the timestamp and
	the source site slug, which is what makes a pulled set recognisable in a
	picker alongside backups this bench took itself — and renaming them would
	break `restore.BACKUP_NAME`, which is how a file is classified at all.
	"""
	parts = backup.get("parts") or {}
	wanted: list[Wanted] = []

	for part in PARTS:
		if part == "public" and not want_public:
			continue
		if part == "private" and not want_private:
			continue

		info = parts.get(part)
		if not info or not info.get("name"):
			continue

		name = str(info["name"])
		# The name becomes a path on THIS disk and it came from another
		# machine, so anything that is not already a plain filename is refused
		# rather than trimmed down to one. `basename` would have quietly turned
		# `../../etc/passwd` into `passwd` and carried on — which is a guess at
		# what a hostile or broken source meant, and writing a file somewhere
		# unexpected is exactly the outcome worth refusing outright.
		if not name or name != os.path.basename(name) or name in (".", "..") or os.path.isabs(name):
			raise TransferRefused(
				f"The source offered {name!r} as the {part} filename. That is a path, not a name, "
				f"so nothing was pulled."
			)

		wanted.append(
			Wanted(
				part=part,
				filename=name,
				size=int(info.get("size") or 0),
				destination=os.path.join(directory, name),
			)
		)

	if not any(w.part == "database" for w in wanted):
		raise TransferRefused(
			"That backup has no database file, so there is nothing to restore from it."
		)
	return wanted


def total_bytes(wanted: list[Wanted]) -> int:
	return sum(w.size for w in wanted)


def already_here(wanted: list[Wanted]) -> int:
	"""Bytes of this set already on disk, from an interrupted earlier attempt."""
	return sum(
		os.path.getsize(w.destination) if os.path.exists(w.destination) else 0 for w in wanted
	)


def check_room(directory: str, wanted: list[Wanted]) -> None:
	"""Refuse a pull that cannot fit, before it starts.

	Counts only what is still missing, so resuming a half-finished transfer is
	not refused for space it has already used. The headroom is on top of the
	files themselves because the restore that follows needs somewhere to expand
	the dump — `restore.estimate_space` checks that separately and in more
	detail, but a pull that fills the disk means never reaching it.
	"""
	missing = max(0, total_bytes(wanted) - already_here(wanted))
	try:
		free = shutil.disk_usage(directory).free
	except OSError as exc:
		raise TransferRefused(f"Could not check free space on {directory}: {exc}") from exc

	if free < missing + HEADROOM:
		raise TransferRefused(
			f"Pulling this needs about {_human(missing)} and there is {_human(free)} free. "
			f"Clear some space, or restore without the files."
		)


def describe(wanted: list[Wanted]) -> str:
	"""One line for the log, naming what is about to move."""
	return ", ".join(f"{w.part} {w.size_text}" for w in wanted) or "nothing"


def _human(count: int) -> str:
	value = float(count)
	for unit in ("B", "KB", "MB", "GB", "TB"):
		if value < 1024 or unit == "TB":
			return f"{value:.1f} {unit}"
		value /= 1024
	return f"{value:.1f} TB"
