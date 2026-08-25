# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""One change to an account. Kept for a year — these are the records that say when a way in was created."""

import frappe
from frappe.model.document import Document


DEFAULT_RETENTION_DAYS = 365


class SystemAccountChange(Document):
	@staticmethod
	def clear_old_logs(days: int = DEFAULT_RETENTION_DAYS) -> None:
		"""Required by Log Settings, which calls this without checking it exists.

		frappe reads `controller.clear_old_logs` unconditionally, so a registered
		doctype missing this method raises AttributeError and aborts the daily
		clearing loop for every doctype after it -- frappe's own logs included.
		"""
		from frappe.query_builder import Interval
		from frappe.query_builder.functions import Now

		table = frappe.qb.DocType("System Account Change")
		frappe.db.delete(table, filters=(table.creation < (Now() - Interval(days=days))))
