# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Per-IP geolocation cache and sighting history.

WHY A DOCTYPE RATHER THAN COLUMNS ON THE EVENT. An address is seen hundreds or
thousands of times; its country is looked up once. Holding it here means one
lookup per address ever, a natural drill-down from any event, and a place for
the sighting history to live. It is deliberately NOT a log doctype — the cache
should outlive the events that populated it, so that an address reappearing
months later is recognised immediately.
"""

import ipaddress

import frappe
from frappe.model.document import Document

STATUS_PENDING = "Pending"
STATUS_RESOLVED = "Resolved"
STATUS_PRIVATE = "Private"
STATUS_FAILED = "Failed"


class IPAddressInfo(Document):
	def validate(self):
		self.ip_address = (self.ip_address or "").strip()
		if not self.ip_address:
			frappe.throw("IP Address is required.")

	def before_insert(self):
		"""Refuse the site's default country on a record that has none.

		THE BUG THIS FIXES. `Document._set_defaults()` builds a fresh doc via
		`frappe.new_doc()` and copies its defaults over any empty field, and
		frappe.new_doc fills a Link->Country field with the session's default
		country. On a business document that is a convenience. Here it is a
		falsehood: a brand-new address that has not been looked up yet, or one
		that is private and never will be, would be recorded as coming from
		whatever country the site was set up in.

		Country is only ever set by the resolver, so anything that arrives here
		unresolved has no country by definition.
		"""
		if self.status != STATUS_RESOLVED:
			self.country = None
			self.country_code = None


def is_private_address(ip: str) -> bool:
	"""Is this address non-routable, and therefore never worth a lookup?

	Covers loopback, RFC1918 / unique-local, link-local, reserved and multicast.
	Anything unparseable is treated as private too — it must not be handed to a
	third-party API, and it certainly is not a real internet peer.
	"""
	try:
		addr = ipaddress.ip_address(ip)
	except ValueError:
		return True
	return bool(
		addr.is_private
		or addr.is_loopback
		or addr.is_link_local
		or addr.is_reserved
		or addr.is_multicast
		or addr.is_unspecified
	)


def ensure_ip(ip: str, seen_at=None) -> str | None:
	"""Return the IP Address Info name for `ip`, creating the row if needed.

	Called inline during ingest, once per distinct address per run, so that the
	Link target on an event is guaranteed to exist before the event is inserted.
	Private addresses are created too — they are still worth seeing in the UI —
	but are marked so no resolver will ever send them anywhere.
	"""
	ip = (ip or "").strip()
	if not ip:
		return None

	# Second lock on the same door. The parser refuses to report anything that
	# is not an address, but this value becomes a DOCNAME, and a bad one raises
	# out of ingest and aborts the whole batch — which never advances the
	# checkpoint, so the same record fails again forever. Anything unparseable
	# is dropped rather than allowed to stop monitoring.
	try:
		ipaddress.ip_address(ip)
	except ValueError:
		frappe.logger("server").warning(f"refusing to record {ip!r} as an IP address")
		return None

	seen_at = seen_at or frappe.utils.now_datetime()

	if frappe.db.exists("IP Address Info", ip):
		# `db_set`-style update: no version rows, no modified churn on a value
		# that changes on every single event.
		frappe.db.set_value("IP Address Info", ip, "last_seen", seen_at, update_modified=False)
		return ip

	doc = frappe.get_doc(
		{
			"doctype": "IP Address Info",
			"ip_address": ip,
			"status": STATUS_PRIVATE if is_private_address(ip) else STATUS_PENDING,
			"first_seen": seen_at,
			"last_seen": seen_at,
		}
	)
	doc.insert(ignore_permissions=True)
	return doc.name
