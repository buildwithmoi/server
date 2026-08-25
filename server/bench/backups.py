# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Taking backups, and clearing out the ones nobody needs.

The health panel can now tell you that backups are eating the disk. This is the
part that lets you do something about it without an SSH session and a carefully
typed `rm`.

Deleting backups is destructive in a quiet way — nothing breaks today, and you
find out months later when the one you wanted is gone. So the rules here are
deliberately conservative and are enforced in the module rather than in the
interface:

  * the newest few sets are never deletable, whatever is asked;
  * a set younger than a day is never deletable, because the reason you are
    clearing space is often a restore you are about to do;
  * a plan is computed and shown first, and the delete only ever acts on the
    exact set of files that plan named.

Frappe-free, so the rules test with no site and no database.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from server.bench import restore

#: Never deletable, no matter what is asked. The most recent backups are the
#: ones you would actually restore from.
MIN_KEEP = 2

#: Nor is anything this new. Clearing space is usually something you do just
#: before a restore, and deleting the backup you are about to need would be a
#: spectacular own goal.
MIN_AGE_HOURS = 24

#: What the interface offers by default.
DEFAULT_KEEP = 5


@dataclass(frozen=True)
class Candidate:
	"""One backup set, and whether it may be removed."""

	key: str
	taken_at: str
	size: int
	size_text: str
	age_hours: float
	age_text: str
	files: list[str]
	deletable: bool
	reason: str


def _age_text(hours: float) -> str:
	if hours < 48:
		return f"{int(hours)}h old"
	days = hours / 24
	if days < 60:
		return f"{int(days)}d old"
	return f"{days / 30:.1f} months old"


def plan(
	bench_path: str,
	site: str,
	keep: int = DEFAULT_KEEP,
	older_than_days: float = 0,
) -> dict:
	"""What a prune would delete, without deleting anything.

	Two conditions, both of which must hold before a set is offered for
	deletion: it is outside the newest `keep`, and it is older than
	`older_than_days`. Keeping them as an AND rather than an OR is what stops
	"keep the last 5" from quietly removing yesterday's backup on a site that
	takes six a day.
	"""
	keep = max(MIN_KEEP, int(keep))
	sets = restore.list_backups(bench_path, site)
	now = time.time()

	candidates: list[Candidate] = []
	for index, backup in enumerate(sets):
		files = [p for p in (backup.database, backup.public_files, backup.private_files, backup.site_config) if p]
		age_hours = _age_hours(files, now)

		if index < keep:
			deletable, reason = False, f"One of the newest {keep} — kept."
		elif age_hours < MIN_AGE_HOURS:
			deletable, reason = False, "Less than a day old — kept."
		elif age_hours < older_than_days * 24:
			deletable, reason = False, f"Newer than {int(older_than_days)} days — kept."
		else:
			deletable, reason = True, "Would be deleted."

		candidates.append(
			Candidate(
				key=backup.key,
				taken_at=backup.taken_at,
				size=backup.size,
				size_text=restore._human_size(backup.size),
				age_hours=round(age_hours, 1),
				age_text=_age_text(age_hours),
				files=files,
				deletable=deletable,
				reason=reason,
			)
		)

	freed = sum(c.size for c in candidates if c.deletable)
	return {
		"site": site,
		"keep": keep,
		"older_than_days": older_than_days,
		"candidates": [c.__dict__ for c in candidates],
		"deletable": [c.key for c in candidates if c.deletable],
		"freed": freed,
		"freed_text": restore._human_size(freed),
		"total": sum(c.size for c in candidates),
		"total_text": restore._human_size(sum(c.size for c in candidates)),
	}


def _age_hours(files: list[str], now: float) -> float:
	"""Age from the newest file in the set.

	The newest, not the oldest: a set is as young as its most recently written
	member, and using the oldest would let a set that is still being written
	look ancient.
	"""
	newest = 0.0
	for path in files:
		try:
			newest = max(newest, os.path.getmtime(path))
		except OSError:
			continue
	return (now - newest) / 3600 if newest else 0.0


def prune(bench_path: str, site: str, keys: list[str], keep: int = DEFAULT_KEEP) -> dict:
	"""Delete the named backup sets, and only those.

	The plan is recomputed here rather than trusted from the caller. The browser
	sent these keys some seconds ago, and in between the scheduler may have
	written a new backup — which would shift what "the newest 5" means and could
	turn a set that was safe to delete into one that is not.
	"""
	current = plan(bench_path, site, keep=keep)
	allowed = {c["key"]: c for c in current["candidates"] if c["deletable"]}

	requested = set(keys or [])
	refused = sorted(requested - set(allowed))
	targets = [allowed[key] for key in requested if key in allowed]

	backups_dir = os.path.join(bench_path, "sites", site, "private", "backups")
	deleted: list[str] = []
	failed: list[dict] = []
	freed = 0

	for target in targets:
		for path in target["files"]:
			# Belt and braces: only ever unlink inside this site's own backup
			# directory, whatever the plan happens to say.
			if not restore.is_inside(backups_dir, path):
				failed.append({"path": path, "error": "outside the site's backup directory"})
				continue
			try:
				size = os.path.getsize(path)
				os.remove(path)
				deleted.append(path)
				freed += size
			except OSError as exc:
				failed.append({"path": path, "error": str(exc)})

	return {
		"site": site,
		"deleted": deleted,
		"deleted_sets": [t["key"] for t in targets],
		"failed": failed,
		"refused": refused,
		"freed": freed,
		"freed_text": restore._human_size(freed),
	}


def build_backup_argv(bench_exe: str, site: str, with_files: bool = False) -> list[str]:
	"""Take a backup now."""
	argv = [bench_exe, "--site", site, "backup"]
	if with_files:
		argv.append("--with-files")
	return argv
