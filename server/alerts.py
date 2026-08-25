# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Telling someone when something is wrong.

This app was written because a server was compromised and nobody found out
until the hosting provider noticed the outbound traffic. It has been collecting
every SSH event and every sudo command ever since — and until now it has never
once told anyone anything. A dashboard only works if somebody is looking at it,
and nobody is looking at it at three in the morning.

Two families of alert, both driven from data already being collected:

  * **Intrusion.** A successful root login, a successful login from a country
    you have never logged in from, and a burst of failures from one address.
    These are the three that are worth waking someone for; everything else is
    noise a busy port produces continuously.

  * **Disk.** The quiet one. A full disk takes down every site on every bench
    at once, it fills gradually enough that nobody notices, and the thing
    filling it is nearly always backups nobody pruned.

Flood control is the hard part and frappe already solves it: `dedupe_on` skips
a notification whose subject already exists. Folding the date into the subject
turns that into "tell me once a day about this", which is what stops a
four-thousand-attempt brute force producing four thousand notifications.
"""

from __future__ import annotations

import frappe
from frappe.desk.doctype.notification_log.notification_log import enqueue_create_notification

from server.server.doctype.server_settings.server_settings import get_settings

#: How far back an intrusion sweep looks. Comfortably more than the five-minute
#: ingest tick, so a slow run cannot open a gap events fall through.
LOOKBACK_MINUTES = 20

#: Disk levels worth an alert. `warn` is a nudge; `critical` is "this will take
#: the server down and you have days, not weeks".
DISK_WARN = 80.0
DISK_CRITICAL = 90.0


def _notify(recipients: list[str], subject: str, message: str, doctype: str, name: str) -> None:
	"""One notification, deduplicated by subject.

	The subject carries the date, so the same condition alerts once a day
	rather than once per scheduler tick. Without that a brute force running all
	night produces a notification per attempt and the mailbox becomes the
	denial of service.
	"""
	if not recipients:
		return

	enqueue_create_notification(
		recipients,
		{
			"type": "Alert",
			"subject": subject,
			"email_content": message,
			"document_type": doctype,
			"document_name": name,
			# Administrator rather than the session user: these are raised by the
			# scheduler, and attributing them to whoever happened to trigger a
			# sweep would be a lie about where they came from.
			"from_user": "Administrator",
		},
		dedupe_on=["document_type", "subject"],
	)


def _today() -> str:
	return frappe.utils.nowdate()


# ----------------------------------------------------------------------
# Intrusion
# ----------------------------------------------------------------------


def check_ssh(minutes: int = LOOKBACK_MINUTES) -> dict:
	"""Sweep recent SSH events for the three patterns worth reporting."""
	settings = get_settings()
	recipients = settings.get_alert_recipients()
	if not recipients:
		return {"alerts": [], "reason": "alerting is off, or no recipient could be resolved"}

	since = frappe.utils.add_to_date(frappe.utils.now_datetime(), minutes=-minutes)
	raised: list[str] = []

	if settings.alert_on_root_login:
		raised += _root_logins(recipients, since)
	if settings.alert_on_new_country:
		raised += _new_countries(recipients, since, settings)
	raised += _failed_bursts(recipients, since, settings)

	return {"alerts": raised, "since": str(since)}


def _root_logins(recipients: list[str], since) -> list[str]:
	"""A successful root login.

	High signal precisely because it should be impossible: `PermitRootLogin no`
	is the first line of any hardening, so one that succeeds means either the
	hardening is not applied or somebody is already inside.
	"""
	rows = frappe.get_all(
		"SSH Auth Event",
		filters={
			"event_time": [">", since],
			"username": "root",
			"outcome": "Success",
			"event_type": ["in", ("Accepted", "Session Opened")],
		},
		fields=["name", "source_ip", "country", "auth_method", "event_time"],
		order_by="event_time desc",
		limit=200,
	)

	# Grouped by address, not one per event. A session that opens and reopens
	# produces several rows for one fact, and they all share a subject — which
	# dedupe_on would collapse anyway, after enqueueing a job for each.
	by_address: dict[str, list] = {}
	for row in rows:
		by_address.setdefault(row.source_ip or "an unknown address", []).append(row)

	raised = []
	for address, events in by_address.items():
		latest = events[0]
		subject = f"Root login succeeded from {address} · {_today()}"
		times = (
			f"at {latest.event_time}"
			if len(events) == 1
			else f"{len(events)} times, most recently at {latest.event_time}"
		)
		_notify(
			recipients,
			subject,
			(
				f"<p><b>root logged in successfully</b> {times} "
				f"from {address} ({latest.country or 'unknown country'}) "
				f"using {latest.auth_method or 'an unrecorded method'}.</p>"
				"<p>Direct root login should normally be refused outright. If this was not you, "
				"treat the machine as compromised: check <code>Sudo Commands</code> for what was "
				"run, and disable password authentication and root login in sshd_config.</p>"
			),
			"SSH Auth Event",
			latest.name,
		)
		raised.append(subject)
	return raised


def _trusted_names(settings) -> set[str]:
	"""Trusted countries as lowercase names AND codes, so either spelling works."""
	from server.geo import countries as geo_countries

	trusted: set[str] = set()
	for code in settings.get_trusted_countries():
		trusted.add(code.lower())
		name = geo_countries.country_from_code(code)
		if name:
			trusted.add(name.lower())
	return trusted


def _new_countries(recipients: list[str], since, settings) -> list[str]:
	"""A successful login from a country never seen before.

	Compared against every country that has ever logged in successfully, not a
	fixed list — so the first login from home is announced once and then never
	again, and a login from somewhere genuinely new always is.
	"""
	# Both spellings. The setting is documented as ISO-2 codes and
	# `get_trusted_countries()` returns codes, but SSH Auth Event stores the
	# country NAME — so comparing the two never matched and the setting
	# suppressed nothing at all. Someone who types "Ghana" instead of "GH"
	# meant the same thing, so accept either.
	trusted = _trusted_names(settings)

	recent = frappe.get_all(
		"SSH Auth Event",
		filters={"event_time": [">", since], "outcome": "Success", "country": ["is", "set"]},
		fields=["name", "username", "country", "source_ip", "event_time"],
		limit=50,
	)
	if not recent:
		return []

	known = _countries_seen_before(since)

	raised = []
	seen_this_run: set[str] = set()
	for row in recent:
		country = (row.country or "").strip()
		key = country.lower()
		if not country or key in known or key in trusted or key in seen_this_run:
			continue
		seen_this_run.add(key)

		subject = f"First successful login from {country} · {_today()}"
		_notify(
			recipients,
			subject,
			(
				f"<p><b>{row.username}</b> logged in successfully from <b>{country}</b> "
				f"({row.source_ip}) at {row.event_time}.</p>"
				"<p>No successful login has ever come from this country before. If you are not "
				"travelling and not using a VPN, rotate the key or password used and check "
				"<code>Sudo Commands</code> for what happened next.</p>"
			),
			"SSH Auth Event",
			row.name,
		)
		raised.append(subject)
	return raised


def _countries_seen_before(since) -> set[str]:
	"""Every country that has ever logged in successfully before `since`.

	DISTINCT rather than reading rows. Taking the 5,000 most recent events was
	wrong on exactly the servers this matters on: a busy host produces that many
	failures in an afternoon, so a country seen last month fell out of the
	window and re-alerted as new — and an alert that cries wolf is one people
	stop reading. The distinct set is small and the query is an index scan.
	"""
	rows = frappe.db.sql(
		"""
		SELECT DISTINCT country FROM `tabSSH Auth Event`
		WHERE event_time <= %(since)s AND outcome = 'Success'
		  AND country IS NOT NULL AND country != ''
		""",
		{"since": since},
	)
	return {(row[0] or "").lower() for row in rows}


def _failed_bursts(recipients: list[str], since, settings) -> list[str]:
	"""Many failures from one address in a short window.

	Reported per address rather than per attempt — the point is "this address is
	working through a wordlist", which is one fact, not four thousand.
	"""
	threshold = int(settings.failed_login_threshold or 0)
	if threshold <= 0:
		return []

	rows = frappe.db.sql(
		"""
		SELECT source_ip, country, COUNT(*) AS attempts, MAX(event_time) AS last_seen
		FROM `tabSSH Auth Event`
		WHERE event_time > %(since)s AND outcome = 'Failure' AND source_ip IS NOT NULL
		GROUP BY source_ip, country
		HAVING attempts >= %(threshold)s
		ORDER BY attempts DESC
		LIMIT 10
		""",
		{"since": since, "threshold": threshold},
		as_dict=True,
	)

	raised = []
	for row in rows:
		subject = f"{row.attempts} failed logins from {row.source_ip} · {_today()}"
		_notify(
			recipients,
			subject,
			(
				f"<p><b>{row.attempts} failed login attempts</b> from {row.source_ip} "
				f"({row.country or 'unknown country'}), most recently at {row.last_seen}.</p>"
				"<p>This is what a wordlist looks like. It is only dangerous while password "
				"authentication is enabled — set <code>PasswordAuthentication no</code> and it "
				"becomes noise. fail2ban will also ban the address if it is running.</p>"
			),
			"IP Address Info",
			row.source_ip,
		)
		raised.append(subject)
	return raised


# ----------------------------------------------------------------------
# Disk
# ----------------------------------------------------------------------


def check_disk() -> dict:
	"""Warn before the disk fills, while there is still time to act.

	The failure this prevents is specific: a bench host fills up, every site on
	it stops serving at once, and the first anyone knows is a customer calling.
	"""
	from server import system

	settings = get_settings()
	recipients = settings.get_alert_recipients()
	if not recipients:
		return {"alerts": [], "reason": "alerting is off, or no recipient could be resolved"}

	benches = frappe.get_all("Server Bench", filters={"is_active": 1}, fields=["name", "bench_path"])
	paths = [b.bench_path for b in benches]
	report = system.snapshot(paths)

	raised = []
	for disk in report["disks"]:
		if disk["percent"] < DISK_WARN:
			continue

		critical = disk["percent"] >= DISK_CRITICAL
		mount = disk["label"]
		# The percentage is NOT in the subject.
		#
		# dedupe_on matches on the subject, and a disk drifting 84.3 → 84.4 →
		# 84.6 over a day produced a different subject every hour — so nothing
		# ever deduplicated and every System Manager got twenty-four
		# notifications, and twenty-four emails, about one condition. The
		# measurement belongs in the body; the subject has to be the stable
		# fact, which is "this mount is low today".
		subject = f"Disk {'critically ' if critical else ''}low on {mount} · {_today()}"

		hints = _disk_hints(paths)
		_notify(
			recipients,
			subject,
			(
				f"<p><b>{mount} is {disk['percent']}% full</b> — {disk['detail']}.</p>"
				+ (
					"<p>When this reaches zero every site on every bench on this machine stops, "
					"and MariaDB may not restart cleanly.</p>"
					if critical
					else "<p>Worth clearing space now, while it is routine.</p>"
				)
				+ hints
			),
			"Server Bench",
			# A docname, not a filesystem path. It was `paths[0]`, so every disk
			# alert linked to a Server Bench that does not exist and the
			# notification led nowhere.
			benches[0].name if benches else None,
		)
		raised.append(subject)

	return {"alerts": raised, "worst": report["worst_level"]}


def _disk_hints(paths: list[str]) -> str:
	"""Name the sites whose backups are using the most space.

	The difference between "your disk is full" and "your disk is full, and
	these three sites are why".
	"""
	from server import system

	rows: list[dict] = []
	for path in paths:
		rows.extend(system.backup_usage(path))
	if not rows:
		return ""

	rows.sort(key=lambda r: r["bytes"], reverse=True)
	items = "".join(
		f"<li>{row['site']} — {row['size_text']} in {row['files']} files</li>" for row in rows[:5]
	)
	return (
		"<p>Backups are usually the cause. Largest first:</p>"
		f"<ul>{items}</ul>"
		"<p>Benches &rarr; a bench &rarr; Actions &rarr; Manage backups will clear the old ones.</p>"
	)


# ----------------------------------------------------------------------
# Scheduler entry points
# ----------------------------------------------------------------------


def run_intrusion_checks() -> dict:
	"""Scheduled. Never raises — an alerting failure must not stop ingestion."""
	try:
		return check_ssh()
	except Exception as exc:
		frappe.logger("server").error(f"intrusion alert sweep failed: {exc}", exc_info=True)
		return {"alerts": [], "error": str(exc)}


def run_disk_checks() -> dict:
	"""Scheduled. Never raises."""
	try:
		return check_disk()
	except Exception as exc:
		frappe.logger("server").error(f"disk alert sweep failed: {exc}", exc_info=True)
		return {"alerts": [], "error": str(exc)}
