# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""One SSH login, from authentication to disconnection.

WHY THIS IS A DOCTYPE AND NOT A REPORT. It is the artefact anyone actually
looks at — "who was on this box, from where, and what did they run" — and a
Query Report cannot be charted, cannot be linked to from a sudo record, and
would recompute the join on every view. It is also kept longer than the events
it was built from: the events are a log and expire, the session is the
conclusion drawn from them.

NOT a log doctype, deliberately. `in_create` and hash naming are for rows that
only ever arrive; a session is updated as it progresses — it opens, it
accumulates commands, it closes — so it is named by its session key and
written in place.
"""

import frappe
from frappe.model.document import Document


#: A year, where the events it was built from keep ninety days. That is the
#: point of the doctype: the events are raw material and expire, the session is
#: the conclusion drawn from them and is what someone reconstructing a
#: months-old intrusion actually reads. The incident behind this app ran
#: undetected for eight months, so a record that expires sooner than the
#: intrusion cannot be used to investigate one.
#:
#: Bounded all the same. One row per login on a public server is not a small
#: number, and "state, not a log" is a reason to keep it in place rather than a
#: reason to keep it forever.
DEFAULT_RETENTION_DAYS = 365


class SSHSession(Document):
	@staticmethod
	def clear_old_logs(days: int = DEFAULT_RETENTION_DAYS) -> None:
		from frappe.query_builder import Interval
		from frappe.query_builder.functions import Now

		table = frappe.qb.DocType("SSH Session")
		# By login_time, not creation: a session is written when it is first
		# sessionised, which for a backfilled log is long after the login it
		# describes. Ageing on creation would keep old logins for a year from
		# the day they were imported.
		frappe.db.delete(table, filters=(table.login_time < (Now() - Interval(days=days))))
