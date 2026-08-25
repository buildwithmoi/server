# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""What changed on disk, and when. Append-only history behind the findings.

A year, matching the other security history in this app: the incident it was
written for ran undetected for eight months, and a record that expires sooner
than the intrusion cannot be used to reconstruct one.
"""

import frappe
from frappe.model.document import Document

DEFAULT_RETENTION_DAYS = 365


class FilesystemChange(Document):
	@staticmethod
	def clear_old_logs(days: int = DEFAULT_RETENTION_DAYS) -> None:
		from frappe.query_builder import Interval
		from frappe.query_builder.functions import Now

		table = frappe.qb.DocType("Filesystem Change")
		frappe.db.delete(table, filters=(table.creation < (Now() - Interval(days=days))))
