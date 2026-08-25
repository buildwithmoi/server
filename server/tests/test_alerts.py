# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Alerting tests.

The delivery path is the part that had two independent bugs in it, and both had
the same shape: everything looked like it worked, and nothing arrived. So these
assert against the real notification machinery rather than mocking it, and the
ones that need a database say so and skip.

The pure parts — flood control by subject, grouping many events into one fact —
are testable with no site at all, and those are the ones that keep a four
thousand attempt brute force from producing four thousand notifications.
"""

from __future__ import annotations

import unittest
from unittest import mock

try:
	import frappe

	_HAS_SITE = bool(getattr(frappe.local, "site", None))
except Exception:  # pragma: no cover
	frappe = None
	_HAS_SITE = False

if frappe is not None:
	from server import alerts


@unittest.skipUnless(frappe is not None, "requires frappe on the path")
class TestNotifyGuard(unittest.TestCase):
	def test_no_recipients_sends_nothing(self):
		"""Alerting off must be silent, not an exception in the scheduler."""
		with mock.patch.object(alerts, "enqueue_create_notification") as sent:
			alerts._notify([], "subject", "body", "SSH Auth Event", "X")
			sent.assert_not_called()

	def test_flood_control_is_requested(self):
		"""Without dedupe_on, a brute force produces a notification per attempt
		and the mailbox becomes the denial of service."""
		with mock.patch.object(alerts, "enqueue_create_notification") as sent:
			alerts._notify(["a@example.com"], "s", "b", "SSH Auth Event", "X")
			self.assertEqual(sent.call_args[1]["dedupe_on"], ["document_type", "subject"])

	def test_alerts_are_never_attributed_to_a_person(self):
		"""Raised by the scheduler; attributing them to whoever triggered a
		sweep would be a lie about where they came from."""
		with mock.patch.object(alerts, "enqueue_create_notification") as sent:
			alerts._notify(["a@example.com"], "s", "b", "SSH Auth Event", "X")
			self.assertEqual(sent.call_args[0][1]["from_user"], "Administrator")


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestDelivery(unittest.TestCase):
	"""The two bugs that made every alert silently vanish."""

	def test_the_subject_carries_the_date(self):
		"""The other half of flood control.

		dedupe_on suppresses a subject that already exists, so folding the date
		in turns that into "tell me once a day about this". A finer timestamp
		would alert every tick; none at all would alert once and then never
		again, however long the problem persisted.
		"""
		with mock.patch.object(alerts, "_notify") as sent:
			alerts._root_logins(["a@example.com"], "since")
		for call in sent.call_args_list:
			self.assertIn(alerts._today(), call[0][1])

	def test_alert_is_a_self_notify_type(self):
		"""Frappe drops a notification whose recipient is also its sender.

		On a server whose only System Manager is Administrator — a fresh
		install — that dropped every alert this app raises.
		"""
		from frappe.desk.doctype.notification_log.notification_log import get_self_notify_types

		self.assertIn("Alert", get_self_notify_types())

	def test_recipients_resolve_to_email_addresses(self):
		"""Frappe matches recipients on User.email.

		For an ordinary user name and email are the same string, so plucking
		the name looked correct — but Administrator is named "Administrator"
		and has a separate email, and matched nobody.
		"""
		from server.server.doctype.server_settings.server_settings import get_settings

		settings = get_settings()
		if not settings.alerts_enabled:
			self.skipTest("alerting is disabled on this site")

		recipients = settings.get_alert_recipients()
		self.assertTrue(recipients)
		for recipient in recipients:
			with self.subTest(recipient=recipient):
				self.assertTrue(
					frappe.db.exists("User", {"email": recipient}),
					f"{recipient} does not match any User.email, so nothing would be delivered",
				)


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestGrouping(unittest.TestCase):
	def test_one_alert_per_address_not_one_per_event(self):
		"""A session that opens and reopens is one fact, not six.

		They would all share a subject and dedupe_on would collapse them in the
		database anyway — after enqueueing a background job for each.
		"""
		events = [
			frappe._dict(name=f"E{i}", source_ip="1.1.1.1", country="X", auth_method="publickey", event_time="t")
			for i in range(6)
		] + [
			frappe._dict(name="E9", source_ip="2.2.2.2", country="Y", auth_method="password", event_time="t")
		]

		with (
			mock.patch.object(alerts.frappe, "get_all", return_value=events),
			mock.patch.object(alerts, "_notify") as sent,
		):
			raised = alerts._root_logins(["a@example.com"], "since")

		self.assertEqual(len(raised), 2)
		self.assertEqual(len(set(raised)), 2)
		self.assertEqual(sent.call_count, 2)

	def test_a_repeated_login_says_how_many_times(self):
		events = [
			frappe._dict(name=f"E{i}", source_ip="1.1.1.1", country="X", auth_method="publickey", event_time="t")
			for i in range(4)
		]
		with (
			mock.patch.object(alerts.frappe, "get_all", return_value=events),
			mock.patch.object(alerts, "_notify") as sent,
		):
			alerts._root_logins(["a@example.com"], "since")
		self.assertIn("4 times", sent.call_args[0][2])

	def test_no_events_raises_nothing(self):
		with (
			mock.patch.object(alerts.frappe, "get_all", return_value=[]),
			mock.patch.object(alerts, "_notify") as sent,
		):
			self.assertEqual(alerts._root_logins(["a@example.com"], "since"), [])
			sent.assert_not_called()


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestSweepsNeverRaise(unittest.TestCase):
	"""An alerting failure must not take ingestion or the scheduler down."""

	def test_intrusion_sweep_swallows_errors(self):
		with mock.patch.object(alerts, "check_ssh", side_effect=RuntimeError("boom")):
			result = alerts.run_intrusion_checks()
		self.assertEqual(result["alerts"], [])
		self.assertIn("boom", result["error"])

	def test_disk_sweep_swallows_errors(self):
		with mock.patch.object(alerts, "check_disk", side_effect=RuntimeError("boom")):
			result = alerts.run_disk_checks()
		self.assertEqual(result["alerts"], [])
		self.assertIn("boom", result["error"])


if __name__ == "__main__":
	unittest.main()


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestFloodControlKeys(unittest.TestCase):
	"""What goes in the subject decides what gets deduplicated."""

	def test_a_measurement_is_never_part_of_the_subject(self):
		"""The disk percentage was, so nothing ever deduplicated.

		A host drifting 84.3 → 84.4 → 84.6 over a day produced a different
		subject every hour, so every System Manager received twenty-four
		notifications and twenty-four emails about one condition — the mailbox
		becoming exactly the denial of service this module was written to avoid.
		"""
		from unittest import mock

		disks = [
			{"label": "/", "percent": pct, "level": "warn", "detail": f"{pct}% used"}
			for pct in (84.3, 84.4, 85.1)
		]
		recipients = mock.Mock(get_alert_recipients=lambda: ["ops@example.com"])
		subjects = []
		for disk in disks:
			with (
				mock.patch.object(
					alerts, "_notify", side_effect=lambda r, s, b, dt, dn: subjects.append(s)
				),
				mock.patch.object(alerts, "get_settings", return_value=recipients),
				mock.patch("server.system.snapshot", return_value={"disks": [disk], "worst_level": "warn"}),
				mock.patch.object(alerts, "_disk_hints", return_value=""),
			):
				alerts.check_disk()

		self.assertTrue(subjects, "no disk alert was raised at all")
		self.assertEqual(
			len(set(subjects)), 1, f"the subject changes with the measurement: {subjects}"
		)
		for subject in subjects:
			self.assertNotIn("84.3", subject)
			self.assertNotIn("%", subject)


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestTrustedCountries(unittest.TestCase):
	"""The setting suppressed nothing, because it compared codes to names.

	`get_trusted_countries()` returns ISO-2 codes and SSH Auth Event stores the
	country NAME, so "GH" was tested against "ghana" and never matched. Someone
	who entered their own country to quieten the noise would conclude the
	setting was broken, stop reading new-country alerts, and lose the one that
	mattered along with them.
	"""

	def _settings(self, value):
		from server.server.doctype.server_settings.server_settings import get_settings

		settings = get_settings()
		settings.trusted_countries = value
		return settings

	def test_iso_codes_match_the_stored_country_name(self):
		trusted = alerts._trusted_names(self._settings("GH\nDE"))
		self.assertIn("ghana", trusted)
		self.assertIn("germany", trusted)

	def test_codes_themselves_still_match(self):
		trusted = alerts._trusted_names(self._settings("GH"))
		self.assertIn("gh", trusted)

	def test_typing_the_name_works_too(self):
		"""Someone entering "Germany" plainly meant Germany."""
		self.assertIn("germany", alerts._trusted_names(self._settings("Germany")))

	def test_an_empty_setting_trusts_nothing(self):
		self.assertEqual(alerts._trusted_names(self._settings("")), set())

	def test_an_unknown_code_does_not_raise(self):
		self.assertIn("zz", alerts._trusted_names(self._settings("ZZ")))


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestNewCountryBaseline(unittest.TestCase):
	def test_the_baseline_is_a_distinct_set_not_a_recent_window(self):
		"""It read the 5,000 most recent events.

		Wrong on exactly the servers this matters on: a busy host produces that
		many failures in an afternoon, so a country seen last month fell out of
		the window and re-alerted as new. An alert that cries wolf is one people
		stop reading, which is how the one that matters gets missed.
		"""
		since = frappe.utils.now_datetime()
		countries = alerts._countries_seen_before(since)
		self.assertIsInstance(countries, set)
		self.assertTrue(all(c == c.lower() for c in countries), countries)

	def test_it_does_not_depend_on_how_many_events_exist(self):
		total = frappe.db.count("SSH Auth Event")
		if total < 10:
			self.skipTest("not enough events on this site to be meaningful")
		since = frappe.utils.now_datetime()
		distinct = frappe.db.sql(
			"""SELECT COUNT(DISTINCT country) FROM `tabSSH Auth Event`
			   WHERE event_time <= %s AND outcome = 'Success'
			     AND country IS NOT NULL AND country != ''""",
			since,
		)[0][0]
		self.assertEqual(len(alerts._countries_seen_before(since)), distinct)


@unittest.skipUnless(_HAS_SITE, "requires a frappe site")
class TestAlertsLinkSomewhereReal(unittest.TestCase):
	def test_the_disk_alert_names_a_docname_not_a_filesystem_path(self):
		"""It passed bench_path, so every disk alert linked to a Server Bench
		that does not exist and the notification led nowhere."""
		from unittest import mock

		bench = frappe.get_all(
			"Server Bench", filters={"is_active": 1}, fields=["name", "bench_path"], limit=1
		)
		if not bench:
			self.skipTest("no active bench")

		captured = []
		recipients = mock.Mock(get_alert_recipients=lambda: ["ops@example.com"])
		with (
			mock.patch.object(
				alerts, "_notify", side_effect=lambda r, s, b, dt, dn: captured.append((dt, dn))
			),
			mock.patch.object(alerts, "get_settings", return_value=recipients),
			mock.patch(
				"server.system.snapshot",
				return_value={
					"disks": [{"label": "/", "percent": 95.0, "level": "critical", "detail": "full"}],
					"worst_level": "critical",
				},
			),
			mock.patch.object(alerts, "_disk_hints", return_value=""),
		):
			alerts.check_disk()

		self.assertTrue(captured)
		doctype, docname = captured[0]
		self.assertEqual(doctype, "Server Bench")
		self.assertTrue(
			frappe.db.exists(doctype, docname), f"{docname!r} is not a real {doctype}"
		)
