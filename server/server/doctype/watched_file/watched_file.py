# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""One thing on disk the filesystem detector is keeping an eye on.

State, not a log — there is one row per path and it is updated in place, so
this doctype is deliberately NOT registered for log clearing. Deleting it
would not save space (it is bounded by what is on the disk), and it would
destroy the baseline that makes change detection mean anything.
"""

import frappe
from frappe.model.document import Document


class WatchedFile(Document):
	pass
