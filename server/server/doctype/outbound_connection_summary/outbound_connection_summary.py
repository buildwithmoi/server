# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Where this host connected out to, aggregated per destination per hour. Raw connections are far too many to keep and the aggregate is what gets investigated — 'this address, this port, this often' is the question anyone actually asks."""

import frappe
from frappe.model.document import Document


DEFAULT_RETENTION_DAYS = 90


class OutboundConnectionSummary(Document):
	@staticmethod
	def clear_old_logs(days: int = DEFAULT_RETENTION_DAYS) -> None:
		"""Required by Log Settings; see the note in system_account_change.py.

		Ninety days rather than a year: this is per destination per hour, so it is
		the one security table that grows with traffic rather than with events.
		"""
		from frappe.query_builder import Interval
		from frappe.query_builder.functions import Now

		table = frappe.qb.DocType("Outbound Connection Summary")
		frappe.db.delete(table, filters=(table.creation < (Now() - Interval(days=days))))
