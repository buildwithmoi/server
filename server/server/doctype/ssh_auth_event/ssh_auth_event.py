# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Append-only record of one sshd/PAM authentication event."""

import frappe
from frappe.model.document import Document
from frappe.utils import add_days, now_datetime

#: Kept in step with the entry in hooks.py `default_log_clearing_doctypes`.
#: 90 days is a deliberate compromise: long enough to investigate a breach
#: discovered weeks late (which is how the last one was discovered), short
#: enough that an exposed port 22 generating tens of thousands of failed
#: attempts a day does not accumulate tens of millions of rows.
DEFAULT_RETENTION_DAYS = 90


class SSHAuthEvent(Document):
	@staticmethod
	def clear_old_logs(days: int = DEFAULT_RETENTION_DAYS) -> None:
		"""Called by frappe's Log Settings on the daily maintenance run.

		Registering the doctype in `default_log_clearing_doctypes` alone is not
		enough — frappe only clears doctypes whose controller implements this
		exact staticmethod (see frappe/core/doctype/log_settings/log_settings.py,
		`LogType` protocol).
		"""
		cutoff = add_days(now_datetime(), -days)
		frappe.db.delete("SSH Auth Event", {"creation": ("<", cutoff)})


def on_doctype_update():
	"""Indexes that individual `search_index` flags cannot express.

	The charts and the intrusion view both filter by outcome and then order by
	time; the composite index is what keeps that fast once the table is large.
	"""
	frappe.db.add_index("SSH Auth Event", ["outcome", "event_time"])
	frappe.db.add_index("SSH Auth Event", ["source_ip", "event_time"])
