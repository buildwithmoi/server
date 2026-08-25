# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The catalogue of bench commands this app is willing to run.

WHY A CATALOGUE AND NOT A PASSTHROUGH. "Run any bench command" is a remote
shell with extra steps. Every argv here is assembled from a fixed entry plus
parameters matched against a pattern, so nothing a browser sends ever reaches
the command line as an argument of its own choosing.

WHY THE UNRUNNABLE ONES ARE STILL LISTED. `bench --site x console` and
`mariadb` open an interactive session; under a background worker they would
read from a closed stdin and abort immediately. Hiding them would leave someone
searching for a command that plainly exists and finding nothing. Listing them
with the reason is more use than silence.

RISK is not decoration. It decides whether the UI demands a typed confirmation,
and `destructive` means this command can lose data that no backup here is
taking first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

RISK_READ = "read"
RISK_ROUTINE = "routine"
RISK_DESTRUCTIVE = "destructive"
RISK_UNSUPPORTED = "unsupported"

SCOPE_BENCH = "bench"
SCOPE_SITE = "site"

VALID_APP = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
VALID_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
#: A hostname. Deliberately its own pattern: VALID_APP rejects the dots, and a
#: domain reaching the command line unchecked is how `--upload-pack=` style
#: arguments get in.
VALID_DOMAIN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
#: on / off, and nothing else.
VALID_TOGGLE = re.compile(r"^(on|off)$")
#: A site name is a hostname too, but may be a single label on a dev bench.
VALID_SITE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")


@dataclass(frozen=True)
class Param:
	name: str
	label: str
	pattern: re.Pattern[str]
	placeholder: str = ""
	required: bool = True


@dataclass(frozen=True)
class BenchCommand:
	id: str
	label: str
	argv: tuple[str, ...]
	scope: str
	description: str
	risk: str
	params: tuple[Param, ...] = ()
	unsupported_reason: str = ""
	#: Roughly how long this can legitimately take, in seconds. Used to pick a
	#: timeout rather than applying the install default to a clear-cache.
	timeout: int = 900

	@property
	def runnable(self) -> bool:
		return self.risk != RISK_UNSUPPORTED


def _p(name, label, pattern=VALID_APP, placeholder=""):
	return Param(name=name, label=label, pattern=pattern, placeholder=placeholder)


# ---------------------------------------------------------------------------
# Site-scoped: bench --site <site> <argv>
# ---------------------------------------------------------------------------

SITE_COMMANDS = [
	BenchCommand(
		"site.doctor",
		"Doctor",
		("doctor",),
		SCOPE_SITE,
		"Diagnostic report on background workers, queues and the scheduler.",
		RISK_READ,
		timeout=180,
	),
	BenchCommand(
		"site.list-apps",
		"List apps",
		("list-apps",),
		SCOPE_SITE,
		"Apps installed on this site, with their versions and branches.",
		RISK_READ,
		timeout=180,
	),
	BenchCommand(
		"site.show-config",
		"Show config",
		("show-config",),
		SCOPE_SITE,
		"The site's configuration as frappe sees it.",
		RISK_READ,
		timeout=120,
	),
	BenchCommand(
		"site.list-sites",
		"List sites",
		("list-sites",),
		SCOPE_SITE,
		"Every site in this bench.",
		RISK_READ,
		timeout=120,
	),
	BenchCommand(
		"site.migrate",
		"Migrate",
		("migrate",),
		SCOPE_SITE,
		"Apply pending patches, sync DocType schema and rebuild the website. Run this after "
		"installing or updating an app.",
		RISK_ROUTINE,
		timeout=3600,
	),
	BenchCommand(
		"site.clear-cache",
		"Clear cache",
		("clear-cache",),
		SCOPE_SITE,
		"Clear the DocType, defaults and general cache.",
		RISK_ROUTINE,
		timeout=300,
	),
	BenchCommand(
		"site.clear-website-cache",
		"Clear website cache",
		("clear-website-cache",),
		SCOPE_SITE,
		"Clear only the website/portal cache.",
		RISK_ROUTINE,
		timeout=300,
	),
	BenchCommand(
		"site.backup",
		"Backup (database)",
		("backup",),
		SCOPE_SITE,
		"Database-only backup into the site's private/backups directory.",
		RISK_ROUTINE,
		timeout=3600,
	),
	BenchCommand(
		"site.backup-files",
		"Backup (with files)",
		("backup", "--with-files"),
		SCOPE_SITE,
		"Database plus public and private files. Much larger and slower than a database-only "
		"backup, and the files can dwarf the database.",
		RISK_ROUTINE,
		timeout=7200,
	),
	BenchCommand(
		"site.build-search-index",
		"Rebuild search index",
		("build-search-index",),
		SCOPE_SITE,
		"Rebuild the global search index.",
		RISK_ROUTINE,
		timeout=1800,
	),
	BenchCommand(
		"site.enable-scheduler",
		"Enable scheduler",
		("enable-scheduler",),
		SCOPE_SITE,
		"Let scheduled jobs run on this site.",
		RISK_ROUTINE,
		timeout=120,
	),
	BenchCommand(
		"site.disable-scheduler",
		"Disable scheduler",
		("disable-scheduler",),
		SCOPE_SITE,
		"Stop scheduled jobs on this site. Nothing periodic will run until re-enabled — including "
		"this app's own SSH ingest.",
		RISK_ROUTINE,
		timeout=120,
	),
	BenchCommand(
		"site.purge-jobs",
		"Purge queued jobs",
		("purge-jobs",),
		SCOPE_SITE,
		"Drop pending background jobs for this site.",
		RISK_ROUTINE,
		timeout=300,
	),
	BenchCommand(
		"site.install-app",
		"Install app on site",
		("install-app",),
		SCOPE_SITE,
		"Install an app that is already in the bench onto this site.",
		RISK_ROUTINE,
		params=(_p("app", "App name", placeholder="erpnext"),),
		timeout=3600,
	),
	BenchCommand(
		"site.build",
		"Build assets",
		("build",),
		SCOPE_SITE,
		"Compile JS and CSS. The heaviest routine operation on a small server — it is the step "
		"most likely to exhaust memory.",
		RISK_ROUTINE,
		timeout=3600,
	),
	BenchCommand(
		"site.uninstall-app",
		"Uninstall app from site",
		("uninstall-app", "--yes"),
		SCOPE_SITE,
		"Remove an app from this site. Deletes the app's DocTypes and every document in them.",
		RISK_DESTRUCTIVE,
		params=(_p("app", "App name", placeholder="erpnext"),),
		timeout=3600,
	),
	BenchCommand(
		"site.destroy-all-sessions",
		"Sign out all users",
		("destroy-all-sessions",),
		SCOPE_SITE,
		"Clear every session on the site. Everyone is logged out, including you.",
		RISK_DESTRUCTIVE,
		timeout=180,
	),
	BenchCommand(
		"site.drop-site",
		"Drop site",
		("drop-site",),
		SCOPE_SITE,
		"Delete the site: its database and its files. There is no undo, and nothing here takes a "
		"backup first.",
		RISK_UNSUPPORTED,
		timeout=1800,
		unsupported_reason=(
			"Not run from here. Two reasons, and both are structural rather than squeamish. "
			"frappe's drop-site takes the site as a positional argument, not the global --site "
			"option this catalogue builds — so the command this app would assemble is one click "
			"refuses to parse, and the entry could never have worked. And it needs the database "
			"root password on the command line, which this catalogue has no way to redact out of "
			"the stored command the way the restore path does. Run it in an SSH session, where "
			"the password stays in your shell history rather than in a log this app displays: "
			"bench drop-site <site> --db-root-password <password>"
		),
	),
	BenchCommand(
		"site.console",
		"Console",
		("console",),
		SCOPE_SITE,
		"An interactive IPython shell for the site.",
		RISK_UNSUPPORTED,
		unsupported_reason="Interactive. A background worker has no terminal and closed stdin, so "
		"this would abort the moment it asked for input. Run it in an SSH session.",
	),
	BenchCommand(
		"site.mariadb",
		"MariaDB console",
		("mariadb",),
		SCOPE_SITE,
		"An interactive database console.",
		RISK_UNSUPPORTED,
		unsupported_reason="Interactive, and it would hand a browser a database prompt. Run it in "
		"an SSH session.",
	),
	BenchCommand(
		"site.restore",
		"Restore",
		("restore",),
		SCOPE_SITE,
		"Restore the site from a backup file.",
		RISK_UNSUPPORTED,
		unsupported_reason="Needs database root credentials and drops the existing database. Not "
		"exposed here yet — it is a planned feature with its own confirmation flow.",
	),
]

# ---------------------------------------------------------------------------
# Bench-scoped: bench <argv>
# ---------------------------------------------------------------------------

BENCH_COMMANDS = [
	BenchCommand(
		"bench.version",
		"Version",
		("--version",),
		SCOPE_BENCH,
		"The bench CLI version.",
		RISK_READ,
		timeout=120,
	),
	BenchCommand(
		"bench.src",
		"Source path",
		("src",),
		SCOPE_BENCH,
		"Where the bench CLI itself is installed.",
		RISK_READ,
		timeout=120,
	),
	BenchCommand(
		"bench.remote-urls",
		"Remote URLs",
		("remote-urls",),
		SCOPE_BENCH,
		"The git remote of every app in this bench.",
		RISK_READ,
		timeout=300,
	),
	BenchCommand(
		"bench.validate-dependencies",
		"Validate dependencies",
		("validate-dependencies",),
		SCOPE_BENCH,
		"Check that every app's declared requirements are satisfied.",
		RISK_READ,
		timeout=600,
	),
	BenchCommand(
		"bench.restart",
		"Restart processes",
		("restart",),
		SCOPE_BENCH,
		"Restart supervisor processes or systemd units for this bench.",
		RISK_ROUTINE,
		timeout=600,
	),
	BenchCommand(
		"bench.backup-all-sites",
		"Backup all sites",
		("backup-all-sites",),
		SCOPE_BENCH,
		"Database backup of every site in this bench.",
		RISK_ROUTINE,
		timeout=7200,
	),
	BenchCommand(
		"bench.setup-requirements",
		"Install requirements",
		("setup", "requirements"),
		SCOPE_BENCH,
		"Reinstall Python and Node dependencies for every app.",
		RISK_ROUTINE,
		timeout=3600,
	),
	BenchCommand(
		"bench.exclude-app",
		"Exclude app from updates",
		("exclude-app",),
		SCOPE_BENCH,
		"Stop `bench update` touching this app.",
		RISK_ROUTINE,
		params=(_p("app", "App name"),),
		timeout=300,
	),
	BenchCommand(
		"bench.include-app",
		"Include app in updates",
		("include-app",),
		SCOPE_BENCH,
		"Undo an exclusion.",
		RISK_ROUTINE,
		params=(_p("app", "App name"),),
		timeout=300,
	),
	BenchCommand(
		"bench.update",
		"Update bench",
		("update", "--no-backup"),
		SCOPE_BENCH,
		"Pull every app, install requirements, run patches and build assets across the whole "
		"bench. Long, heavy, and it touches every app at once — a single app's Pull is almost "
		"always the safer choice.",
		RISK_DESTRUCTIVE,
		timeout=7200,
	),
	BenchCommand(
		"bench.switch-to-branch",
		"Switch all apps to branch",
		("switch-to-branch",),
		SCOPE_BENCH,
		"Move every app in the bench onto the named branch.",
		RISK_DESTRUCTIVE,
		params=(_p("branch", "Branch", VALID_BRANCH, "version-15"),),
		timeout=3600,
	),
	BenchCommand(
		"bench.remove-app",
		"Remove app from bench",
		("remove-app",),
		SCOPE_BENCH,
		"Delete the app from the bench directory. bench archives it to archived/apps rather than "
		"deleting outright, but the site must not still have it installed.",
		RISK_DESTRUCTIVE,
		params=(_p("app", "App name"),),
		timeout=1800,
	),
	BenchCommand(
		"bench.disable-production",
		"Disable production",
		("disable-production",),
		SCOPE_BENCH,
		"Remove the supervisor and nginx configuration for this bench. The site stops being served.",
		RISK_DESTRUCTIVE,
		timeout=600,
	),
	BenchCommand(
		"bench.start",
		"Start",
		("start",),
		SCOPE_BENCH,
		"Run the development processes in the foreground.",
		RISK_UNSUPPORTED,
		unsupported_reason="Never exits — it runs the web server, workers and watcher until "
		"interrupted, so it would hold a worker slot until the timeout killed it.",
	),
	BenchCommand(
		"bench.new-app",
		"New app",
		("new-app",),
		SCOPE_BENCH,
		"Scaffold a new frappe app.",
		RISK_UNSUPPORTED,
		unsupported_reason="Interactive — it asks a series of questions about the app it is creating.",
	),
	BenchCommand(
		"bench.install",
		"Install system dependencies",
		("install",),
		SCOPE_BENCH,
		"Install OS-level packages needed by a bench.",
		RISK_UNSUPPORTED,
		unsupported_reason="Needs root. This app deliberately runs as the bench user and has no "
		"way to escalate, which is why it can be given a web interface at all.",
	),
]

# ---------------------------------------------------------------------------
# Serving a domain. Four commands, because a DNS record is only the first step
# and the rest of them are what actually make a site answer to a name.
# ---------------------------------------------------------------------------

DOMAIN_COMMANDS = [
	BenchCommand(
		"bench.add-domain",
		"Add a domain to a site",
		# NOTE the `--site` inside the fixed argv, and that this is BENCH-scoped
		# rather than site-scoped. `bench setup add-domain` takes its own
		# `--site` option; the global one this app normally uses is rejected
		# outright — `bench --site x setup ...` fails with "No such option".
		# Ending the fixed argv with the flag lets the first parameter supply
		# its value, and the second becomes the positional domain.
		("setup", "add-domain", "--site"),
		SCOPE_BENCH,
		"Tell frappe this site answers to a domain. Without it the domain resolves here and "
		"frappe serves the default site instead, which looks like a DNS problem and is not.",
		RISK_ROUTINE,
		params=(
			_p("site", "Site", VALID_SITE_NAME, "local.16.server"),
			_p("domain", "Domain", VALID_DOMAIN, "app.example.com"),
		),
		timeout=180,
	),
	BenchCommand(
		"bench.dns-multitenant",
		"DNS multitenancy",
		("config", "dns_multitenant"),
		SCOPE_BENCH,
		"Serve sites by the hostname asked for rather than always the default site. Off on a "
		"fresh bench, and bench refuses to set up SSL without it — while exiting 0, so it looks "
		"like it worked.",
		RISK_ROUTINE,
		params=(_p("state", "On or off", VALID_TOGGLE, "on"),),
		timeout=120,
	),
	BenchCommand(
		"bench.setup-nginx",
		"Regenerate nginx config",
		("setup", "nginx", "--yes"),
		SCOPE_BENCH,
		"Rewrite this bench's nginx configuration from its current sites and domains. Writes the "
		"file only; nginx keeps serving the old one until it is reloaded.",
		RISK_ROUTINE,
		timeout=180,
	),
	BenchCommand(
		"bench.reload-nginx",
		"Reload nginx",
		("setup", "reload-nginx"),
		SCOPE_BENCH,
		"Check the generated config and reload the service.",
		RISK_UNSUPPORTED,
		unsupported_reason=(
			"Needs root. This app deliberately runs as the bench user and has no way to escalate, "
			"which is why it can be given a web interface at all. Run it yourself: "
			"sudo bench setup reload-nginx"
		),
		timeout=120,
	),
]

ALL_COMMANDS = SITE_COMMANDS + BENCH_COMMANDS + DOMAIN_COMMANDS
BY_ID = {c.id: c for c in ALL_COMMANDS}


def get(command_id: str) -> BenchCommand | None:
	return BY_ID.get(command_id)


def as_dicts() -> list[dict]:
	"""The catalogue, shaped for the picker."""
	return [
		{
			"id": c.id,
			"label": c.label,
			"scope": c.scope,
			"description": c.description,
			"risk": c.risk,
			"runnable": c.runnable,
			"unsupported_reason": c.unsupported_reason,
			"preview": " ".join(("bench", *(("--site", "<site>") if c.scope == SCOPE_SITE else ()), *c.argv)),
			"params": [
				{"name": p.name, "label": p.label, "placeholder": p.placeholder, "required": p.required}
				for p in c.params
			],
		}
		for c in ALL_COMMANDS
	]


class CommandRefused(Exception):
	"""The command cannot be built — with a reason worth showing."""


def build_argv(
	command: BenchCommand,
	bench_executable: str,
	site: str | None = None,
	params: dict | None = None,
) -> list[str]:
	"""Assemble the argv. Every value is checked against its pattern first."""
	if not command.runnable:
		raise CommandRefused(command.unsupported_reason or f"{command.label} cannot be run from here.")

	argv = [bench_executable]
	if command.scope == SCOPE_SITE:
		if not site:
			raise CommandRefused(f"{command.label} needs a site.")
		argv += ["--site", site]
	argv += list(command.argv)

	supplied = params or {}
	for spec in command.params:
		value = (supplied.get(spec.name) or "").strip()
		if not value:
			if spec.required:
				raise CommandRefused(f"{command.label} needs {spec.label.lower()}.")
			continue
		if not spec.pattern.match(value):
			raise CommandRefused(f"{value!r} is not a valid {spec.label.lower()}.")
		argv.append(value)

	return argv
