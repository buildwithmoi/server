# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Reading and changing a site's configuration.

`site_config.json` is where you go to put a site into maintenance mode, turn
developer mode on, or check which database it actually uses — and until now
that meant an SSH session and a text editor on a file that will break the site
if you leave a trailing comma in it.

Two rules make this safe enough to expose:

  * **Secrets are never returned.** The same file holds `db_password` and
    `encryption_key`. This app exists because a server was compromised; shipping
    the database password to a browser to render it in a table would be a
    remarkable way to repeat that. They are reported as present, never as a
    value.

  * **Only known keys can be written.** An arbitrary key/value editor over this
    file is a way to break a site by typo — `maintenance_mode: "yes"` is truthy
    JSON and wrong. Each editable key declares its type and is coerced and
    validated before anything is written.

Writes are atomic and take a copy first, because a half-written
`site_config.json` is a site that will not boot at all.

Frappe-free, so it tests against a temp directory with no site.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass

#: Never returned, never editable here. Matched on the whole key and by suffix,
#: so a key nobody anticipated (`stripe_secret_key`, `smtp_password`) is
#: redacted by default rather than leaked by omission.
SECRET_EXACT = {
	"db_password",
	"encryption_key",
	"mariadb_root_password",
	"root_password",
	"admin_password",
	"webhook_secret",
	# Bare names, which the suffix list cannot catch — "password" does not end
	# in "_password". These are how a credential is spelled one level down, in
	# an smtp block or a domains entry.
	"password",
	"passwd",
	"secret",
	"token",
	"api_secret",
	"private_key",
}
SECRET_SUFFIX = ("_password", "_secret", "_key", "_token", "_credentials")

#: A suffix match would otherwise redact these, and they are not secrets.
SECRET_EXEMPT = {"encryption_key_present", "public_key", "host_key", "db_key"}

REDACTED = "••••••••"


@dataclass(frozen=True)
class Setting:
	"""One key this app is willing to change."""

	key: str
	label: str
	kind: str  # bool | int | string
	description: str
	#: True when getting this wrong takes the site off the air.
	disruptive: bool = False
	choices: tuple[str, ...] = ()


#: The curated list. Deliberately short: every key here is one somebody has a
#: real reason to change from a browser, and everything else stays the business
#: of `bench set-config` where a mistake is at least deliberate.
EDITABLE: tuple[Setting, ...] = (
	Setting(
		"maintenance_mode",
		"Maintenance mode",
		"bool",
		"Takes the site off the air and shows a maintenance page. Turn it on before a risky "
		"operation so nobody writes to the database while you work, and remember to turn it "
		"off again — nothing here does that for you.",
		disruptive=True,
	),
	Setting(
		"pause_scheduler",
		"Pause the scheduler",
		"bool",
		"Stops scheduled jobs for this site without stopping the site itself. Useful while "
		"migrating or restoring, so a background job does not run against a half-changed "
		"database.",
	),
	Setting(
		"developer_mode",
		"Developer mode",
		"bool",
		"Writes DocType changes back to disk as JSON and shows full tracebacks. Correct on a "
		"development bench and wrong on a production one — it makes the site slower and leaks "
		"internals into error pages.",
	),
	Setting(
		"disable_website_cache",
		"Disable website cache",
		"bool",
		"Renders every portal page fresh. Useful when debugging a page that will not update, "
		"and a real cost to leave on.",
	),
	Setting(
		"host_name",
		"Host name",
		"string",
		"The URL the site believes it is served at, used in emails and redirects. Include the "
		"scheme, for example https://erp.example.com. This is also the domain SSL will certify.",
		disruptive=True,
	),
	Setting(
		"max_file_size",
		"Maximum upload size",
		"int",
		"Largest file a user may upload, in bytes. Frappe's default is 25 MB (26214400). nginx "
		"has its own limit that has to be raised alongside this one.",
	),
	Setting(
		"scheduler_tick_interval",
		"Scheduler tick",
		"int",
		"Seconds between scheduler ticks. Lower means scheduled jobs fire closer to their time "
		"and the workers do more polling. The default is 60.",
	),
	Setting(
		"logging",
		"Log verbosity",
		"int",
		"0 is quiet, 1 logs queries, 2 logs everything. Anything above 0 grows the log files "
		"quickly — turn it back down when you are done.",
	),
)

BY_KEY = {setting.key: setting for setting in EDITABLE}


class ConfigRefused(Exception):
	"""Raised when a configuration change will not be made."""


def is_secret(key: str) -> bool:
	lowered = key.lower()
	if lowered in SECRET_EXEMPT:
		return False
	return lowered in SECRET_EXACT or lowered.endswith(SECRET_SUFFIX)


#: How a secret shows up in command output. `bench show-config` prints an
#: ASCII table; other commands print JSON or key=value. All three are matched
#: because any of them can carry a password into a log this app displays.
#: Matched per line, and the value runs to the END of the line.
#:
#: The value group used to stop at a quote or a pipe, so a password containing
#: either — `P@ss'w0rd!` — had only its leading fragment replaced and the tail
#: was written into the stored log verbatim. A partly-redacted secret is a
#: leaked secret. A trailing table delimiter is put back afterwards so
#: `bench show-config` output still lines up.
_SECRET_LINE = re.compile(
	r"^(?P<lead>[|\s\"']*)(?P<key>[A-Za-z0-9_.-]+)(?P<sep>\s*[\"']?\s*[|:=]\s*)(?P<value>.+)$"
)

#: Put back after redaction, so a table row keeps its shape.
_TRAILING = re.compile(r"(?P<trail>[\"',]?\s*\|?\s*)$")

#: A secret sitting AFTER a command-line flag, rather than after a key name.
#:
#: `_SECRET_LINE` matches `password = 'x'` and misses
#: `argv = ['bench', 'restore', '--db-root-password', 'admin123']` entirely —
#: the key there is `argv`, which is not a secret name, so the whole line was
#: passed through untouched. That matters because frappe records tracebacks
#: WITH LOCAL VARIABLES, and `argv` is a local in the function that runs every
#: bench command. A crash anywhere inside `_stream` would have written the
#: database root password into the Error Log in plain text.
#:
#: Matched on the flag rather than on the surrounding syntax so it works the
#: same in a Python list repr, a shell line and a JSON array.
_SECRET_ARGUMENT = re.compile(
	r"(?P<flag>--(?:db-root-password|mariadb-root-password|admin-password|encryption-key|password))"
	# The gap has to allow the flag's OWN closing quote before the separator:
	# in a Python list repr the text between flag and value is `', '`, and a
	# pattern that started at the separator matched nothing and let the value
	# through untouched.
	r"(?P<gap>[\"']?[\s,=]+[\"']?)(?P<value>[^\"',\]\s]+)",
	re.IGNORECASE,
)


def _scrub_arguments(line: str) -> str:
	"""Redact a value that follows a secret command-line flag."""
	return _SECRET_ARGUMENT.sub(lambda m: f"{m.group('flag')}{m.group('gap')}{REDACTED}", line)


def scrub(text: str) -> str:
	"""Replace the value of any secret-looking key in command output.

	`bench show-config` prints `db_password` and `encryption_key` in plain
	text, and every command's output is stored in the database and rendered in
	the interface — so a single catalogued read-only command undid the whole
	point of redacting them in the config editor.

	Applied to output rather than to a list of commands, because the next
	command that prints a credential will not be one anybody predicted.
	"""

	def replace_line(line: str) -> str:
		# Flags first, and unconditionally: a secret after `--db-root-password`
		# has to go whether or not the line also looks like `key = value`, and
		# on a line like `argv = [..., '--db-root-password', 'x']` the key is
		# `argv`, which the check below would pass straight through.
		line = _scrub_arguments(line)

		match = _SECRET_LINE.match(line)
		if not match or not is_secret(match["key"]):
			return line
		trail = _TRAILING.search(match["value"])
		return f"{match['lead']}{match['key']}{match['sep']}{REDACTED}{trail['trail'] if trail else ''}"

	return "\n".join(replace_line(line) for line in text.split("\n"))


def redact_nested(value):
	"""Redact secrets inside dicts and lists, not only at the top level.

	The top-level check missed the shapes site_config actually grows: an smtp
	block with a `password` in it, or a `domains` list whose entries carry
	certificate keys. Those came back verbatim, which is the whole failure this
	redaction exists to prevent — just one level down.
	"""
	if isinstance(value, dict):
		return {
			key: REDACTED if is_secret(key) else redact_nested(inner) for key, inner in value.items()
		}
	if isinstance(value, list):
		return [redact_nested(item) for item in value]
	return value


def config_path(bench_path: str, site: str) -> str:
	return os.path.join(bench_path, "sites", site, "site_config.json")


def read(bench_path: str, site: str) -> dict:
	"""The site's configuration, with every secret replaced by a marker.

	The presence of a secret is reported, because "is an encryption key set on
	this site" is a real question with a safe answer. The value never is.
	"""
	path = config_path(bench_path, site)
	try:
		with open(path) as handle:
			raw = json.load(handle)
	except FileNotFoundError:
		return {"path": path, "exists": False, "values": [], "editable": _editable_rows({})}
	except (OSError, ValueError) as exc:
		return {"path": path, "exists": True, "error": str(exc), "values": [], "editable": []}

	values = []
	for key in sorted(raw):
		secret = is_secret(key)
		values.append(
			{
				"key": key,
				"value": REDACTED if secret else redact_nested(raw[key]),
				"secret": secret,
				"editable": key in BY_KEY,
				"description": BY_KEY[key].description if key in BY_KEY else "",
			}
		)

	return {
		"path": path,
		"exists": True,
		"error": None,
		"values": values,
		"editable": _editable_rows(raw),
	}


def _editable_rows(raw: dict) -> list[dict]:
	"""Every settable key with its current value, including the unset ones.

	Unset keys are included on purpose: "maintenance mode is off" and
	"maintenance mode has never been set" are the same thing operationally, and
	hiding the second means the switch you came for is not on the page.
	"""
	rows = []
	for setting in EDITABLE:
		present = setting.key in raw
		value = raw.get(setting.key)
		rows.append(
			{
				**setting.__dict__,
				"value": value,
				"present": present,
				"effective": _effective(setting, value),
			}
		)
	return rows


def _effective(setting: Setting, value) -> object:
	if value is None:
		return False if setting.kind == "bool" else None
	if setting.kind == "bool":
		return bool(value)
	return value


def coerce(setting: Setting, value) -> object:
	"""Turn a browser's value into what frappe expects to read back.

	frappe reads these with plain truthiness and plain arithmetic, so the JSON
	types have to be right. `"false"` is a non-empty string and therefore true,
	which is exactly the mistake this exists to prevent.
	"""
	if setting.kind == "bool":
		if isinstance(value, str):
			return value.strip().lower() in ("1", "true", "yes", "on")
		return bool(value)

	if setting.kind == "int":
		try:
			number = int(str(value).strip())
		except (TypeError, ValueError) as exc:
			raise ConfigRefused(f"{setting.label} must be a whole number.") from exc
		if number < 0:
			raise ConfigRefused(f"{setting.label} cannot be negative.")
		return number

	text = str(value or "").strip()
	if setting.key == "host_name" and text:
		if not re.match(r"^https?://[A-Za-z0-9.-]+(:\d+)?(/.*)?$", text):
			raise ConfigRefused(
				"Host name must be a full URL including the scheme, for example "
				"https://erp.example.com."
			)
	return text


def write(bench_path: str, site: str, changes: dict) -> dict:
	"""Apply changes to site_config.json, atomically.

	A key set to None is removed rather than written as null — frappe treats a
	missing key and a null one differently in a few places, and "unset" is what
	the interface means when a field is cleared.
	"""
	unknown = sorted(set(changes) - set(BY_KEY))
	if unknown:
		raise ConfigRefused(
			f"{', '.join(unknown)} cannot be changed from here. Use `bench set-config` if you "
			"are sure — an arbitrary editor over this file is a way to break a site by typo."
		)

	path = config_path(bench_path, site)
	try:
		with open(path) as handle:
			raw = json.load(handle)
	except FileNotFoundError as exc:
		raise ConfigRefused(f"{path} does not exist.") from exc
	except (OSError, ValueError) as exc:
		raise ConfigRefused(f"{path} could not be read: {exc}") from exc

	applied = {}
	for key, value in changes.items():
		setting = BY_KEY[key]
		# An emptied field means "unset" whatever its type. It only did for
		# strings, so clearing a number returned "must be a whole number" and
		# there was no way to unset one from the interface at all.
		if value is None or (setting.kind in ("string", "int") and not str(value).strip()):
			raw.pop(key, None)
			applied[key] = None
			continue
		raw[key] = coerce(setting, value)
		applied[key] = raw[key]

	backup = _backup(path)
	_atomic_write(path, raw)
	return {"path": path, "applied": applied, "backup": backup}


def install_certificate(bench_path: str, site: str, paths: dict) -> dict:
	"""Write the two SSL paths into a site config.

	SEPARATE FROM `write` ON PURPOSE. That one refuses any key outside the
	editable catalogue, which is right for a form somebody types into — an
	arbitrary editor over this file is a way to break a site by typo. These two
	keys are not typed by anybody: they are produced by certbot and installed
	by the job that just ran it.

	The paths are checked to be inside /etc/letsencrypt rather than trusted,
	because a site config pointing nginx at a file of somebody else's choosing
	is worth one line to prevent.
	"""
	allowed = ("ssl_certificate", "ssl_certificate_key")
	unknown = sorted(set(paths) - set(allowed))
	if unknown:
		raise ConfigRefused(f"{', '.join(unknown)} is not part of installing a certificate.")

	for key, value in paths.items():
		resolved = os.path.realpath(str(value))
		if not resolved.startswith("/etc/letsencrypt/"):
			raise ConfigRefused(f"{key} must be inside /etc/letsencrypt, not {resolved}.")

	path = config_path(bench_path, site)
	try:
		with open(path) as handle:
			raw = json.load(handle)
	except FileNotFoundError as exc:
		raise ConfigRefused(f"{path} does not exist.") from exc
	except (OSError, ValueError) as exc:
		raise ConfigRefused(f"{path} could not be read: {exc}") from exc

	raw.update(paths)
	backup = _backup(path)
	_atomic_write(path, raw)
	return {"path": path, "applied": dict(paths), "backup": backup}


def _backup(path: str) -> str | None:
	"""Copy the file aside before touching it.

	Cheap, and the difference between "undo that" and "restore the site".
	"""
	target = f"{path}.bak-{time.strftime('%Y%m%d_%H%M%S')}"
	try:
		shutil.copy2(path, target)
	except OSError:
		return None
	return target


def _atomic_write(path: str, data: dict) -> None:
	"""Write via a temp file in the same directory, then rename.

	A partial `site_config.json` is a site that will not boot at all, and a
	process killed midway through a plain write leaves exactly that. `rename`
	within one filesystem is atomic, so the file is either the old one or the
	new one and never half of each.
	"""
	directory = os.path.dirname(path)
	handle = tempfile.NamedTemporaryFile(
		"w", dir=directory, prefix=".site_config-", suffix=".tmp", delete=False
	)
	try:
		with handle:
			json.dump(data, handle, indent=1, sort_keys=True)
			handle.flush()
			os.fsync(handle.fileno())
		shutil.copymode(path, handle.name)
		os.replace(handle.name, path)
	except Exception:
		try:
			os.unlink(handle.name)
		except OSError:
			pass
		raise
