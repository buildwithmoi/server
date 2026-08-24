# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Reading the shape of a frappe bench off disk.

Frappe-free by design, same as `server/ssh/parser.py`: everything here is
filesystem and subprocess work that can be exercised against real bench
directories (there are nine on this machine) without a site, a database or a
running server.

WHY NOT IMPORT THE `bench` PACKAGE. It is installed — `frappe-bench` lives in
the system python 3.12 — but the bench venv runs python 3.14 and cannot import
it. Even if it could, importing a CLI tool to ask where its directories are
would couple us to its internals for something that is five `os.path.isdir`
calls.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field

#: A directory is a bench if and only if it contains ALL of these. Taken from
#: bench's own `is_bench_directory()` (bench/utils/__init__.py) so that this
#: agrees with the CLI about what counts — including `config/pids`, which is
#: what stops a bare `apps/sites/config` skeleton being mistaken for one.
BENCH_MARKERS = ("apps", "sites", "config", "logs", "config/pids")

#: bench clones with `--origin upstream`, so this is the remote that exists.
#: `origin` is the fallback for a repo someone set up by hand.
REMOTE_NAMES = ("upstream", "origin")

GIT_TIMEOUT = 15


@dataclass
class AppInfo:
	app_name: str
	git_url: str | None = None
	remote_name: str | None = None
	branch: str | None = None
	commit: str | None = None
	is_shallow: bool = False
	is_dirty: bool = False


@dataclass
class SiteInfo:
	site_name: str
	installed_apps: list[str] = field(default_factory=list)
	is_default: bool = False


@dataclass
class BenchInfo:
	bench_name: str
	bench_path: str
	frappe_branch: str | None = None
	python_version: str | None = None
	shallow_clone: bool = False
	webserver_port: int | None = None
	socketio_port: int | None = None
	redis_queue_port: int | None = None
	redis_cache_port: int | None = None
	frappe_user: str | None = None
	default_site: str | None = None
	apps: list[AppInfo] = field(default_factory=list)
	sites: list[SiteInfo] = field(default_factory=list)
	error: str | None = None


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------


def is_bench_directory(path: str) -> bool:
	"""Does `path` look like a bench, by bench's own definition?"""
	return all(os.path.isdir(os.path.join(path, marker)) for marker in BENCH_MARKERS)


def find_benches(root: str) -> list[str]:
	"""Return the bench directories directly under `root`, sorted.

	Deliberately NOT recursive. bench's own `find_benches` walks the tree, but a
	bench contains an `apps/` full of git checkouts and a `sites/` full of user
	data — descending into those to look for more benches is a lot of IO to
	discover nothing, and on a box with a large sites directory it is slow
	enough to notice.
	"""
	if not os.path.isdir(root):
		return []

	found = []
	try:
		entries = sorted(os.scandir(root), key=lambda e: e.name)
	except OSError:
		return []

	for entry in entries:
		if not entry.is_dir(follow_symlinks=False):
			continue
		if entry.name.startswith("."):
			continue
		if is_bench_directory(entry.path):
			found.append(entry.path)
	return found


def _read_json(path: str) -> dict:
	try:
		with open(path, encoding="utf-8") as fh:
			return json.load(fh)
	except OSError, ValueError:
		return {}


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------


def _git(cwd: str, *args: str) -> str | None:
	"""Run a read-only git command, returning stripped stdout or None.

	`shell=False` with a list argv, and stdin closed: a repo in a odd state must
	never be able to make this block waiting for input inside a worker.
	"""
	try:
		result = subprocess.run(
			["git", *args],
			cwd=cwd,
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=GIT_TIMEOUT,
			check=False,
		)
	except OSError, subprocess.SubprocessError:
		return None
	if result.returncode != 0:
		return None
	return result.stdout.strip() or None


def read_app(app_path: str) -> AppInfo:
	"""Describe one app checkout."""
	info = AppInfo(app_name=os.path.basename(app_path.rstrip("/")))

	if not os.path.isdir(os.path.join(app_path, ".git")):
		return info

	for remote in REMOTE_NAMES:
		url = _git(app_path, "remote", "get-url", remote)
		if url:
			info.git_url = url
			info.remote_name = remote
			break

	info.branch = _git(app_path, "rev-parse", "--abbrev-ref", "HEAD")
	info.commit = _git(app_path, "rev-parse", "--short", "HEAD")
	info.is_shallow = os.path.exists(os.path.join(app_path, ".git", "shallow"))
	info.is_dirty = bool(_git(app_path, "status", "--porcelain"))
	return info


# ---------------------------------------------------------------------------
# Bench
# ---------------------------------------------------------------------------


def read_sites(bench_path: str, default_site: str | None) -> list[SiteInfo]:
	sites_dir = os.path.join(bench_path, "sites")
	found = []
	try:
		entries = sorted(os.scandir(sites_dir), key=lambda e: e.name)
	except OSError:
		return []

	for entry in entries:
		if not entry.is_dir(follow_symlinks=False):
			continue
		config_path = os.path.join(entry.path, "site_config.json")
		if not os.path.isfile(config_path):
			continue
		config = _read_json(config_path)
		found.append(
			SiteInfo(
				site_name=entry.name,
				installed_apps=list(config.get("installed_apps") or []),
				is_default=entry.name == default_site,
			)
		)
	return found


def read_bench(bench_path: str) -> BenchInfo:
	"""Describe one bench: its ports, its apps and its sites."""
	bench_path = bench_path.rstrip("/")
	info = BenchInfo(bench_name=os.path.basename(bench_path), bench_path=bench_path)

	if not is_bench_directory(bench_path):
		info.error = "not a bench directory"
		return info

	config = _read_json(os.path.join(bench_path, "sites", "common_site_config.json"))
	info.default_site = config.get("default_site")
	info.frappe_user = config.get("frappe_user")
	info.shallow_clone = bool(config.get("shallow_clone"))
	info.webserver_port = config.get("webserver_port")
	info.socketio_port = config.get("socketio_port")
	info.redis_queue_port = _port_from_redis_url(config.get("redis_queue"))
	info.redis_cache_port = _port_from_redis_url(config.get("redis_cache"))

	apps_dir = os.path.join(bench_path, "apps")
	app_names = _read_apps_txt(bench_path) or _list_app_dirs(apps_dir)
	for name in app_names:
		app_path = os.path.join(apps_dir, name)
		if os.path.isdir(app_path):
			info.apps.append(read_app(app_path))

	info.sites = read_sites(bench_path, info.default_site)
	info.frappe_branch = next((a.branch for a in info.apps if a.app_name == "frappe"), None)
	info.python_version = _read_python_version(bench_path)
	return info


def _read_apps_txt(bench_path: str) -> list[str]:
	path = os.path.join(bench_path, "sites", "apps.txt")
	try:
		with open(path, encoding="utf-8") as fh:
			return [line.strip() for line in fh if line.strip()]
	except OSError:
		return []


def _list_app_dirs(apps_dir: str) -> list[str]:
	try:
		return sorted(e.name for e in os.scandir(apps_dir) if e.is_dir(follow_symlinks=False))
	except OSError:
		return []


def _port_from_redis_url(url: str | None) -> int | None:
	"""Pull the port out of `redis://127.0.0.1:11008`."""
	if not url or ":" not in url:
		return None
	tail = url.rsplit(":", 1)[-1].strip("/")
	return int(tail) if tail.isdigit() else None


def _read_python_version(bench_path: str) -> str | None:
	python = os.path.join(bench_path, "env", "bin", "python")
	if not os.path.exists(python):
		return None
	try:
		result = subprocess.run(
			[python, "--version"],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=GIT_TIMEOUT,
			check=False,
		)
	except OSError, subprocess.SubprocessError:
		return None
	return (result.stdout or result.stderr).strip().replace("Python ", "") or None


def scan(root: str) -> list[BenchInfo]:
	"""Describe every bench under `root`."""
	return [read_bench(path) for path in find_benches(root)]
