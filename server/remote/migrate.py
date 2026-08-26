# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Working out what it would take to move a whole bench to this machine.

The per-site move answers "bring this site here". This answers the question
before it: given a bench on another server, what has to exist here first — and
is any of it already here?

WHY THIS IS A PLAN RATHER THAN A DO. Moving eight benches is not one button,
it is a sequence of long jobs, and the useful thing is not to start them all —
it is to see, before starting any, what will be built, what will be pulled, how
much disk it needs, and which apps are missing. A migration that stops halfway
because a repository is unreachable, after four gigabytes and forty minutes, is
the failure this module exists to make impossible.

So it produces a plan, the interface shows it, and each site is still moved by
the same ordinary restore job that a single site would use. Nothing here runs
anything.

Frappe-free: it takes the two benches as plain dicts — one read from the remote
over the proxy, one read locally — and returns what it worked out.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: What a site is expected to cost on disk once its dump is expanded, as a
#: multiple of the compressed backup. `restore.DB_EXPANSION` uses 16 for the
#: same reason; this is the rough version, for a plan rather than a decision.
EXPANSION = 16


@dataclass(frozen=True)
class AppPlan:
	"""One app the target bench needs before any of these sites can restore."""

	app_name: str
	branch: str = ""
	git_url: str = ""
	present: bool = False
	branch_matches: bool = True

	@property
	def action(self) -> str:
		if not self.present:
			return "clone"
		if not self.branch_matches:
			return "check branch"
		return "have it"


@dataclass(frozen=True)
class SitePlan:
	site_name: str
	apps: tuple[str, ...] = ()
	#: Set when a site of this name is already on the target bench. Restoring
	#: over it replaces it, which is a different decision from creating one.
	exists_here: bool = False

	@property
	def action(self) -> str:
		return "replace" if self.exists_here else "create then restore"


@dataclass(frozen=True)
class MigrationPlan:
	source_server: str
	source_bench: str
	target_bench: str
	frappe_version: str = ""
	bench_exists: bool = False
	apps: tuple[AppPlan, ...] = ()
	sites: tuple[SitePlan, ...] = ()
	notes: tuple[str, ...] = ()

	@property
	def missing_apps(self) -> tuple[AppPlan, ...]:
		return tuple(a for a in self.apps if not a.present)

	@property
	def branch_differences(self) -> tuple[AppPlan, ...]:
		return tuple(a for a in self.apps if a.present and not a.branch_matches)

	@property
	def ready(self) -> bool:
		"""Whether every site could be moved without anything else first."""
		return self.bench_exists and not self.missing_apps

	def as_dict(self) -> dict:
		return {
			"source_server": self.source_server,
			"source_bench": self.source_bench,
			"target_bench": self.target_bench,
			"frappe_version": self.frappe_version,
			"bench_exists": self.bench_exists,
			"apps": [{**a.__dict__, "action": a.action} for a in self.apps],
			"sites": [{**s.__dict__, "apps": list(s.apps), "action": s.action} for s in self.sites],
			"missing_apps": [a.app_name for a in self.missing_apps],
			"branch_differences": [a.app_name for a in self.branch_differences],
			"ready": self.ready,
			"notes": list(self.notes),
		}


def build(
	source_server: str,
	remote_bench: dict,
	local_bench: dict | None,
	target_bench_name: str = "",
) -> MigrationPlan:
	"""Compare a bench there against a bench here, and say what is needed.

	`local_bench` is None when the target does not exist yet — which is the
	case the whole feature is for, and is treated as "everything is missing"
	rather than as an error.
	"""
	remote_apps = {a["app_name"]: a for a in (remote_bench.get("apps") or []) if a.get("app_name")}
	local_apps = {a["app_name"]: a for a in ((local_bench or {}).get("apps") or []) if a.get("app_name")}
	local_sites = {s["site_name"] for s in ((local_bench or {}).get("sites") or [])}

	apps = []
	for name, app in sorted(remote_apps.items()):
		# frappe is not an app to clone — it is what a bench IS, and it arrives
		# with `bench init` at the version the bench was built for.
		if name == "frappe":
			continue
		mine = local_apps.get(name)
		apps.append(
			AppPlan(
				app_name=name,
				branch=app.get("branch") or "",
				git_url=app.get("git_url") or "",
				present=bool(mine),
				branch_matches=(not mine) or not app.get("branch") or mine.get("branch") == app.get("branch"),
			)
		)

	sites = []
	for site in remote_bench.get("sites") or []:
		name = site.get("site_name")
		if not name:
			continue
		installed = tuple(a for a in (site.get("installed_apps") or []) if a)
		sites.append(SitePlan(site_name=name, apps=installed, exists_here=name in local_sites))

	notes = []
	if not local_bench:
		notes.append(
			f"{target_bench_name or 'The target bench'} does not exist here yet — it is built first, "
			f"on frappe {remote_bench.get('frappe_branch') or 'the same version'}."
		)
	replacing = [s.site_name for s in sites if s.exists_here]
	if replacing:
		notes.append(
			f"{', '.join(replacing)} already exist here and would be REPLACED, not added. "
			f"Each restore takes its own backup first unless that is turned off."
		)
	if not sites:
		notes.append("That bench has no sites on it, so there is nothing to move except the apps.")

	return MigrationPlan(
		source_server=source_server,
		source_bench=remote_bench.get("name") or "",
		target_bench=target_bench_name or remote_bench.get("name") or "",
		frappe_version=str(remote_bench.get("frappe_branch") or "").replace("version-", ""),
		bench_exists=bool(local_bench),
		apps=tuple(apps),
		sites=tuple(sites),
		notes=tuple(notes),
	)


def order_sites(plan: MigrationPlan) -> list[SitePlan]:
	"""The order to move sites in: new ones first, replacements last.

	A migration that is going to be interrupted should be interrupted having
	added sites rather than having half-replaced existing ones — the first is
	progress, the second is damage.
	"""
	return sorted(plan.sites, key=lambda s: (s.exists_here, s.site_name))
