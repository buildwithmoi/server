# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""One change to the persistence surface.

Kept for a year. These are the records that let you say when something
appeared, and reconstructing a compromise that ran for eight months is exactly
the situation they exist for.
"""

import frappe
from frappe.model.document import Document

DEFAULT_RETENTION_DAYS = 365


class PersistenceChange(Document):
	@staticmethod
	def clear_old_logs(days: int = DEFAULT_RETENTION_DAYS) -> None:
		from frappe.query_builder import Interval
		from frappe.query_builder.functions import Now

		table = frappe.qb.DocType("Persistence Change")
		frappe.db.delete(table, filters=(table.creation < (Now() - Interval(days=days))))
