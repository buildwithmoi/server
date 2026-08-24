# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Append-only record of one sudo invocation.

This is the "what did they actually do" half of the audit. Without auditd, sudo
is the richest activity signal a stock Linux box produces, and it is already
being written today with no extra configuration.
"""

import frappe
from frappe.model.document import Document
from frappe.utils import add_days, now_datetime

#: Longer than SSH Auth Event on purpose. Auth events are high-volume and mostly
#: noise from scanners; sudo commands are low-volume and are the record you
#: actually want when reconstructing what an intruder did.
DEFAULT_RETENTION_DAYS = 180


class SSHSudoCommand(Document):
	@staticmethod
	def clear_old_logs(days: int = DEFAULT_RETENTION_DAYS) -> None:
		cutoff = add_days(now_datetime(), -days)
		frappe.db.delete("SSH Sudo Command", {"creation": ("<", cutoff)})


def on_doctype_update():
	frappe.db.add_index("SSH Sudo Command", ["actor", "event_time"])
