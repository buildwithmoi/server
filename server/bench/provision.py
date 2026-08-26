# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Building a new bench and a first site on it.

Every bench on this box was made by hand, and the steps are always the same:
`bench init` with the right interpreter, move the ports off the ones another
bench already has, `new-site` with the database root password, `get-app` each
private repo, `install-app` each one. None of it is difficult and all of it is
easy to get subtly wrong in a way that is discovered later.

FOUR THINGS THIS GETS RIGHT THAT ARE EASY TO GET WRONG BY HAND.

  The interpreter is a PATH, not a name. `bench init --python` wants an
  executable. There is no `python3.14` on this machine's PATH — only
  `/usr/bin/python3.12` — while frappe v16 pins `>=3.14,<3.15`, and the
  interpreter that satisfies it is uv-managed and lives under a long versioned
  directory. Passing the name gives "no such file or directory" a minute into
  a clone; asking uv gives the path.

  Ports are allocated, not defaulted. `bench init` writes 8000/9000/11000/13000
  every time. Start a second bench on those and it collides with the first —
  and the collision that matters is redis, because two benches sharing a redis
  database silently share each other's cache and queue.

  Ports live in THREE places. `common_site_config.json` holds the numbers,
  `config/redis_*.conf` holds them again for the redis servers themselves, and
  the Procfile holds the commands that start them. Setting only the first is
  the classic half-fix: the config says 11005 and redis is still listening on
  11000. So `bench setup redis` and `bench setup procfile` are part of the
  sequence rather than an afterthought.

  Assets are skipped by default. An asset build is the largest memory consumer
  in the whole process, and this machine has about 2.6 GB free of 7.6 GB. A
  bench that fails at the last step for want of memory has still spent four
  gigabytes and several minutes.

Frappe-free, so the port arithmetic and the refusals test with no site and no
database — which matters here more than usual, because the thing being built
takes minutes and four gigabytes to try for real.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

#: Frappe versions this app will build. v16 is what the app itself runs on;
#: v15 is still current for existing deployments.
VERSIONS = ("16", "15")

#: What each version needs. v16's pyproject pins ">=3.14,<3.15"; v15 predates
#: that and runs on 3.11 or 3.12, which is what a stock Ubuntu 24.04 has.
PYTHON_FOR_VERSION = {"16": "3.14", "15": "3.12"}

#: The port block for a bench, derived from one index. Every bench on this box
#: follows it: index 8 is 8008/9008/11008/13008.
WEB_BASE = 8000
SOCKETIO_BASE = 9000
REDIS_QUEUE_BASE = 11000
REDIS_CACHE_BASE = 13000

#: Indices to consider. 1-98 keeps every derived port inside its own thousand,
#: so the arithmetic can never collide two different blocks.
MAX_INDEX = 98

#: A bench is roughly four gigabytes once frappe and its node modules are in.
#: Measured on this box; the margin is for the site and the first app.
BENCH_BYTES = 6 * 1024**3

#: Below this, an asset build will be killed rather than fail cleanly.
MIN_MEMORY_BYTES = 1024**3

VALID_BENCH_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
#: A site name is a hostname. Frappe uses it as a directory name and nginx uses
#: it as a server_name, so it has to satisfy both.
VALID_SITE_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")


class Refusal(Exception):
	"""This cannot be built, with a reason worth showing the operator."""


def generate_admin_password(length: int = 20) -> str:
	"""A random Administrator password, for when the caller supplied none.

	`secrets`, not `random`: this is a credential, and on a site whose restore
	fails it is the only way in.
	"""
	import secrets
	import string

	alphabet = string.ascii_letters + string.digits
	return "".join(secrets.choice(alphabet) for _ in range(length))


@dataclass(frozen=True)
class Ports:
	index: int
	webserver: int
	socketio: int
	redis_queue: int
	redis_cache: int

	def as_dict(self) -> dict:
		return self.__dict__.copy()


def ports_for(index: int) -> Ports:
	return Ports(
		index=index,
		webserver=WEB_BASE + index,
		socketio=SOCKETIO_BASE + index,
		redis_queue=REDIS_QUEUE_BASE + index,
		redis_cache=REDIS_CACHE_BASE + index,
	)


def index_of(webserver_port: int | None) -> int | None:
	"""The block index a bench occupies, from its web port."""
	if not webserver_port:
		return None
	index = int(webserver_port) - WEB_BASE
	return index if 1 <= index <= MAX_INDEX else None


def allocate_index(used_ports: list[int]) -> int:
	"""The lowest free block, not the next one after the highest.

	Benches get removed, and this box already has a gap at 5 (1-4 and 6-8 are
	taken). Counting upward from the maximum would leave that hole forever and
	march the numbers up every time somebody rebuilds one.
	"""
	taken = {index_of(port) for port in used_ports}
	taken.discard(None)
	for index in range(1, MAX_INDEX + 1):
		if index not in taken:
			return index
	raise Refusal(f"All {MAX_INDEX} port blocks are in use. Remove a bench before adding another.")


def resolve_interpreter(frappe_version: str, uv: str = "uv") -> str:
	"""The path to an interpreter that satisfies this frappe version.

	`bench init --python` takes an executable path. Passing a bare name works
	only if it happens to be on PATH — and the interpreter v16 needs is not on
	this machine's PATH at all, so the failure would arrive a minute into a
	clone with "no such file or directory" and no hint about which python.
	"""
	wanted = PYTHON_FOR_VERSION.get(str(frappe_version).strip())
	if not wanted:
		raise Refusal(
			f"Frappe {frappe_version!r} is not one this app knows how to build "
			f"({', '.join(VERSIONS)})."
		)

	if not shutil.which(uv):
		raise Refusal(
			"uv is not installed, and it is what resolves the right Python. "
			"Install it, or point --python at an interpreter by hand."
		)

	try:
		result = subprocess.run(  # noqa: S603
			[uv, "python", "find", wanted],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			text=True,
			timeout=60,
			check=False,
		)
	except (OSError, subprocess.SubprocessError) as exc:
		raise Refusal(f"Could not ask uv for Python {wanted}: {exc}") from exc

	path = (result.stdout or "").strip().splitlines()
	candidate = path[0].strip() if path else ""

	if result.returncode != 0 or not candidate:
		raise Refusal(
			f"Python {wanted} is needed for frappe version-{frappe_version} and is not installed. "
			f"Install it with: uv python install {wanted}"
		)
	if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
		raise Refusal(f"uv reported {candidate} for Python {wanted}, but it is not executable.")

	return candidate


# ----------------------------------------------------------------------
# The commands
# ----------------------------------------------------------------------


def build_init_argv(
	bench_exe: str,
	bench_name: str,
	interpreter: str,
	frappe_version: str,
	skip_assets: bool = True,
) -> list[str]:
	"""`bench init`, run from the parent directory of the new bench."""
	argv = [
		bench_exe,
		"init",
		bench_name,
		"--python",
		interpreter,
		"--frappe-branch",
		f"version-{frappe_version}",
		# A new bench has no automatic backups configured, and this app takes
		# them deliberately. Leaving bench's own cron out keeps one scheduler.
		"--no-backups",
	]
	if skip_assets:
		argv.append("--skip-assets")
	return argv


def build_port_argv(bench_exe: str, ports: Ports) -> list[str]:
	"""Move the new bench off the default port block.

	STRING VALUES HAVE TO ARRIVE AS PYTHON LITERALS, quotes included.
	`bench config set-common-config` runs `ast.literal_eval` on whatever it is
	given, so a bare `redis://127.0.0.1:11009` is parsed as Python source and
	dies with `SyntaxError: invalid syntax` pointing at the `//`. A number is
	fine unquoted because `8009` is already a valid literal — which is exactly
	why this is easy to miss: the first three arguments work and the last three
	do not.

	`redis_socketio` shares the CACHE port, which is what every bench on this
	box does. It looks like a mistake and is not: bench's own generated config
	points socketio at the cache instance.
	"""
	return [
		bench_exe,
		"config",
		"set-common-config",
		"-c", "webserver_port", str(ports.webserver),
		"-c", "socketio_port", str(ports.socketio),
		"-c", "redis_queue", f'"redis://127.0.0.1:{ports.redis_queue}"',
		"-c", "redis_cache", f'"redis://127.0.0.1:{ports.redis_cache}"',
		"-c", "redis_socketio", f'"redis://127.0.0.1:{ports.redis_cache}"',
	]


def build_redis_argv(bench_exe: str) -> list[str]:
	"""Regenerate config/redis_*.conf from the ports just set.

	Without this the numbers live only in common_site_config and the redis
	servers keep listening on the defaults — so the bench points at 13005 and
	redis is on 13000, sharing another bench's cache.
	"""
	return [bench_exe, "setup", "redis"]


def build_procfile_argv(bench_exe: str) -> list[str]:
	"""Regenerate the Procfile, which carries the ports in its commands."""
	return [bench_exe, "setup", "procfile"]


def build_new_site_argv(
	bench_exe: str,
	site: str,
	db_root_password: str,
	admin_password: str = "",
	db_root_username: str = "",
) -> list[str]:
	"""`bench new-site`.

	The passwords are on the command line because bench offers no other way —
	the same constraint `restore.py` documents. `restore.SECRET_FLAGS` already
	covers `--db-root-password` and `--admin-password`, so `restore.redact()`
	hides both from the stored command with no change.
	"""
	if not db_root_password:
		raise Refusal("Creating a site needs the database root password.")

	argv = [bench_exe, "new-site", site, "--db-root-password", db_root_password]
	if db_root_username:
		argv += ["--db-root-username", db_root_username]

	# ALWAYS supplied, generated when the caller did not give one. Without the
	# flag `bench new-site` calls `getpass` for the Administrator password, and
	# under a job — where stdin is closed — that is an immediate EOFError
	# several minutes into creating the site. It fails fast rather than
	# hanging, which is the design working, but it still fails.
	#
	# Generating one is safe precisely where it matters: a site created to
	# receive a restore has its Administrator replaced by the dump moments
	# later, so the value is true for about thirty seconds. The generated one
	# is printed to the log so it is recoverable if the restore never happens.
	argv += ["--admin-password", admin_password or generate_admin_password()]

	# The first site on a new bench becomes the default, so `bench <command>`
	# works without `--site` on every subsequent call — including the ones an
	# operator makes by hand later.
	argv.append("--set-default")

	# NOT `--force`. It drops an existing database of the same name without
	# asking, and this app does not delete a database as a side effect of
	# creating one. If the name is taken, `new-site` should fail and say so.
	return argv


def build_get_app_argv(bench_exe: str, app_name: str, git_url: str, branch: str = "") -> list[str]:
	argv = [bench_exe, "get-app", app_name, git_url]
	if branch:
		argv += ["--branch", branch]
	# Same reasoning as the installer: an asset build is the memory spike.
	argv.append("--skip-assets")
	return argv


def build_install_app_argv(bench_exe: str, site: str, app_name: str) -> list[str]:
	return [bench_exe, "--site", site, "install-app", app_name]


# ----------------------------------------------------------------------
# Pre-flight
# ----------------------------------------------------------------------


def validate_names(bench_name: str, site_name: str = "") -> tuple[str, str]:
	"""Refuse anything that would become a bad directory or a bad hostname."""
	bench = (bench_name or "").strip().lower()
	site = (site_name or "").strip().lower()

	if not VALID_BENCH_NAME.match(bench):
		raise Refusal(
			f"{bench_name!r} is not a usable bench name. Lower case letters, digits, dots, "
			"dashes and underscores, starting with a letter or digit."
		)
	if site and not VALID_SITE_NAME.match(site):
		raise Refusal(
			f"{site_name!r} is not a usable site name. It becomes a directory and an nginx "
			"server_name, so it has to be a hostname."
		)
	return bench, site


def preflight(
	bench_root: str,
	bench_name: str,
	site_name: str,
	db_root_password: str,
	frappe_version: str = "16",
	skip_assets: bool = True,
	uv: str = "uv",
) -> list:
	"""Everything answerable before four gigabytes are spent.

	Returns `ssl.Check` rows — the same shape the SSL readiness panel uses, so
	the interface renders both the same way and a failure names the command
	that fixes it.
	"""
	from server.bench.ssl import Check

	checks: list = []

	try:
		bench, site = validate_names(bench_name, site_name)
	except Refusal as exc:
		return [Check(key="names", label="Names are usable", ok=False, detail=str(exc))]

	target = os.path.join(bench_root, bench)
	checks.append(
		Check(
			key="target",
			label="Directory is free",
			ok=not os.path.exists(target),
			detail=(
				f"{target} already exists. Pick another name, or remove it first — "
				"bench init will not write into it."
				if os.path.exists(target)
				else target
			),
		)
	)

	try:
		interpreter = resolve_interpreter(frappe_version, uv=uv)
		checks.append(
			Check(key="python", label=f"Python for version-{frappe_version}", ok=True, detail=interpreter)
		)
	except Refusal as exc:
		checks.append(Check(key="python", label="Python", ok=False, detail=str(exc)))

	try:
		usage = shutil.disk_usage(bench_root if os.path.isdir(bench_root) else "/")
		enough = usage.free >= BENCH_BYTES
		checks.append(
			Check(
				key="disk",
				label="Room on the disk",
				ok=enough,
				detail=(
					f"{usage.free / 1024**3:.1f} GB free; a bench with its first site needs about "
					f"{BENCH_BYTES / 1024**3:.0f} GB."
				),
			)
		)
	except OSError as exc:
		checks.append(Check(key="disk", label="Room on the disk", ok=False, detail=str(exc)))

	available = _available_memory()
	checks.append(
		Check(
			key="memory",
			label="Memory",
			ok=available == 0 or available >= MIN_MEMORY_BYTES,
			detail=(
				f"{available / 1024**3:.1f} GB available."
				+ ("" if skip_assets else " Building assets needs considerably more than this.")
				if available
				else "Could not read /proc/meminfo."
			),
			# Advisory: a tight box can still build a bench, slowly. It is a
			# reason this might not finish, not proof that it cannot.
			blocking=False,
		)
	)

	# Three states, not two. The wizard asks for the password on its LAST
	# panel, so while the first panel is being filled in there is legitimately
	# no password yet — reporting that as a failure would make the check look
	# broken, and reporting it as "Supplied" would be a lie.
	if not site:
		password_detail = "Not needed — no site is being created."
	elif db_root_password:
		password_detail = (
			"Asked for on the last step. bench new-site has no way to take it other than on "
			"the command line, and it is deleted the moment the job finishes."
		)
	else:
		password_detail = "Needed to create the site. You will be asked for it before anything starts."

	checks.append(
		Check(
			key="password",
			label="Database root password",
			ok=(not site) or bool(db_root_password),
			detail=password_detail,
		)
	)

	return checks


def bench_landed(bench_path: str) -> bool:
	"""Is this a working bench, whatever `bench init` exited with?

	THE MIRROR OF AN INVARIANT THIS APP ALREADY HAS. `get-app` exits 1 from a
	trailing `supervisorctl` call after the app is installed, which is why
	`installer._clone_landed` exists. `bench init` does the same thing and it
	is worse, because it costs four gigabytes and several minutes: it clones
	frappe, builds the virtualenv, installs every dependency, writes the
	config — and then runs `sudo supervisorctl status`, which on any machine
	without passwordless sudo exits non-zero and takes the whole command down
	with it. Observed here: a bench with Python 3.14.6 and frappe 16.31.0
	importable, reported as a failure.

	So the exit code answers "did the command end cleanly", which is a
	different question from "is there a bench here". This asks the second one,
	and asks it of the filesystem rather than the log.
	"""
	markers = ("apps", "sites", "config", "logs", "env")
	if not all(os.path.isdir(os.path.join(bench_path, marker)) for marker in markers):
		return False

	# The virtualenv having a python is what separates "bench init got far
	# enough to matter" from "a few directories were created before it died".
	if not os.access(os.path.join(bench_path, "env", "bin", "python"), os.X_OK):
		return False

	# And frappe itself, which is the point of a bench.
	return os.path.isdir(os.path.join(bench_path, "apps", "frappe"))


def _available_memory() -> int:
	"""MemAvailable in bytes, or 0 when it cannot be read.

	MemAvailable rather than MemFree, for the reason `system.py` documents:
	MemFree excludes the page cache and makes a healthy machine look full.
	"""
	try:
		with open("/proc/meminfo") as handle:
			for line in handle:
				if line.startswith("MemAvailable:"):
					return int(line.split()[1]) * 1024
	except (OSError, ValueError, IndexError):
		return 0
	return 0
