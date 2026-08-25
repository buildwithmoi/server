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


class SSHSession(Document):
	pass
