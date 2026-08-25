# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What the machine itself is doing.

This app is called `server` and until now it could tell you everything about
who logged in and nothing about whether the box was about to fall over. Disk is
the one that actually bites: a full disk breaks every site on every bench at
once, it fills gradually so nobody notices, and on a bench host the thing
filling it is almost always backups nobody deletes.

Frappe-free and dependency-free — /proc and `shutil` only, no psutil. It reads,
it never writes, and every reader degrades to None rather than raising, because
a stats panel must not be able to take a page down.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass

#: Warn here, shout here. A bench host that crosses 90% is days from an outage.
DISK_WARN = 80.0
DISK_CRITICAL = 90.0

#: Same idea for memory, but with more tolerance: Linux is supposed to use RAM.
MEMORY_WARN = 85.0
MEMORY_CRITICAL = 95.0


@dataclass(frozen=True)
class Reading:
	"""One measured value, with the judgement already applied.

	The judgement belongs here rather than in the interface: "82% of disk" means
	nothing on its own, and every place that displays it would otherwise have to
	re-derive what counts as bad.
	"""

	label: str
	value: float
	total: float
	used: float
	free: float
	percent: float
	level: str
	detail: str


def _level(percent: float, warn: float, critical: float) -> str:
	if percent >= critical:
		return "critical"
	if percent >= warn:
		return "warn"
	return "ok"


def human(count: float) -> str:
	value = float(count)
	for unit in ("B", "KB", "MB", "GB", "TB"):
		if value < 1024 or unit == "TB":
			return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
		value /= 1024
	return f"{value:.1f} TB"


# ----------------------------------------------------------------------
# Disk
# ----------------------------------------------------------------------


def disk(path: str = "/") -> Reading | None:
	try:
		usage = shutil.disk_usage(path)
	except OSError:
		return None
	percent = (usage.used / usage.total * 100) if usage.total else 0.0
	level = _level(percent, DISK_WARN, DISK_CRITICAL)
	detail = f"{human(usage.free)} free of {human(usage.total)}"
	if level == "critical":
		detail += " — every site on this machine stops when this reaches zero."
	elif level == "warn":
		detail += " — worth clearing old backups before this becomes urgent."
	return Reading(path, percent, usage.total, usage.used, usage.free, round(percent, 1), level, detail)


def mounts_for(paths: list[str]) -> list[Reading]:
	"""One reading per distinct filesystem behind the given paths.

	Deduplicated by device: benches usually all live on one disk, and showing
	the same 90% nine times is noise, not information.
	"""
	seen: dict[int, Reading] = {}
	for path in ["/", *paths]:
		if not os.path.isdir(path):
			continue
		try:
			device = os.stat(path).st_dev
		except OSError:
			continue
		if device in seen:
			continue
		reading = disk(path)
		if reading:
			seen[device] = reading
	return list(seen.values())


# ----------------------------------------------------------------------
# Memory, load, uptime
# ----------------------------------------------------------------------


def _meminfo() -> dict[str, int]:
	try:
		with open("/proc/meminfo") as handle:
			lines = handle.readlines()
	except OSError:
		return {}
	values = {}
	for line in lines:
		key, _, rest = line.partition(":")
		parts = rest.split()
		if parts and parts[0].isdigit():
			values[key] = int(parts[0]) * 1024
	return values


def memory() -> Reading | None:
	info = _meminfo()
	total = info.get("MemTotal", 0)
	if not total:
		return None
	# MemAvailable, not MemFree. MemFree excludes the page cache, which Linux
	# will hand back the instant anything asks — reporting it as "used" makes a
	# perfectly healthy machine look like it is out of memory.
	available = info.get("MemAvailable", info.get("MemFree", 0))
	used = total - available
	percent = used / total * 100
	return Reading(
		"memory",
		percent,
		total,
		used,
		available,
		round(percent, 1),
		_level(percent, MEMORY_WARN, MEMORY_CRITICAL),
		f"{human(available)} available of {human(total)}",
	)


def swap() -> Reading | None:
	info = _meminfo()
	total = info.get("SwapTotal", 0)
	if not total:
		return None
	free = info.get("SwapFree", 0)
	used = total - free
	percent = used / total * 100
	# Swap in use is not itself a problem; swap nearly full while memory is also
	# tight is what precedes the OOM killer.
	return Reading(
		"swap",
		percent,
		total,
		used,
		free,
		round(percent, 1),
		_level(percent, 90.0, 98.0),
		f"{human(used)} used of {human(total)}",
	)


def load() -> dict | None:
	"""Load average, expressed per CPU so the number means something.

	A load of 8 is idle on a 16-core box and on fire on a 2-core one, which is
	why the raw figure is close to useless on its own.
	"""
	try:
		one, five, fifteen = os.getloadavg()
	except (OSError, AttributeError):
		return None
	cpus = os.cpu_count() or 1
	per_cpu = one / cpus
	return {
		"one": round(one, 2),
		"five": round(five, 2),
		"fifteen": round(fifteen, 2),
		"cpus": cpus,
		"per_cpu": round(per_cpu, 2),
		"level": _level(per_cpu * 100, 100.0, 200.0),
		"detail": f"{one:.2f} over {cpus} CPUs",
	}


def uptime() -> dict | None:
	try:
		with open("/proc/uptime") as handle:
			seconds = float(handle.read().split()[0])
	except (OSError, ValueError, IndexError):
		return None
	days, rest = divmod(int(seconds), 86400)
	hours, rest = divmod(rest, 3600)
	minutes = rest // 60
	if days:
		text = f"{days}d {hours}h"
	elif hours:
		text = f"{hours}h {minutes}m"
	else:
		text = f"{minutes}m"
	return {"seconds": int(seconds), "text": text, "booted_at": time.time() - seconds}


# ----------------------------------------------------------------------
# Where the space went
# ----------------------------------------------------------------------


def directory_size(path: str, timeout: int = 20) -> int | None:
	"""Size of a directory tree, via `du`.

	Shelled out rather than walked in Python: a bench with node_modules is
	hundreds of thousands of files, and `du` does in a second what os.walk does
	in thirty. Bounded by a timeout so a pathological tree cannot wedge a
	request.
	"""
	try:
		proc = subprocess.run(  # noqa: S603
			["du", "-sb", path],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=timeout,
			check=False,
		)
	except (OSError, subprocess.SubprocessError):
		return None
	if proc.returncode != 0 and not proc.stdout:
		return None
	first = proc.stdout.split("\t", 1)[0].strip()
	return int(first) if first.isdigit() else None


def backup_usage(bench_path: str) -> list[dict]:
	"""How much disk each site's backups are using.

	The most useful number on the page. Backups are the thing that fills a bench
	host, and nothing else in the interface would ever tell you which site is
	responsible.
	"""
	sites_dir = os.path.join(bench_path, "sites")
	if not os.path.isdir(sites_dir):
		return []

	rows = []
	for entry in os.scandir(sites_dir):
		if not entry.is_dir() or entry.name.startswith("."):
			continue
		backups = os.path.join(entry.path, "private", "backups")
		if not os.path.isdir(backups):
			continue
		total = 0
		count = 0
		oldest = None
		for file in os.scandir(backups):
			if not file.is_file():
				continue
			try:
				stat = file.stat()
			except OSError:
				continue
			total += stat.st_size
			count += 1
			oldest = stat.st_mtime if oldest is None else min(oldest, stat.st_mtime)
		if count:
			rows.append(
				{
					"site": entry.name,
					"path": backups,
					"bytes": total,
					"size_text": human(total),
					"files": count,
					"oldest_days": round((time.time() - oldest) / 86400) if oldest else None,
				}
			)

	rows.sort(key=lambda r: r["bytes"], reverse=True)
	return rows


def snapshot(bench_paths: list[str] | None = None) -> dict:
	"""Everything at once, for one panel. Never raises."""
	paths = bench_paths or []
	readings = mounts_for(paths)
	worst = max((r.level for r in readings), key=["ok", "warn", "critical"].index, default="ok")
	return {
		"disks": [r.__dict__ for r in readings],
		"memory": (memory() or {}) and memory().__dict__,
		"swap": (swap() or {}) and swap().__dict__,
		"load": load(),
		"uptime": uptime(),
		"hostname": os.uname().nodename,
		"worst_level": worst,
	}
