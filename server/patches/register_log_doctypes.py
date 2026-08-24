# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Register this app's log doctypes with Log Settings immediately.

Idempotent: `LogSettings.register_doctype` updates an existing row rather than
appending a duplicate, so re-running this changes nothing.

WHY A PATCH IS NEEDED AT ALL. Declaring `default_log_clearing_doctypes` in
hooks.py is necessary but not sufficient — frappe only reads that hook from
`run_log_clean_up()`, which is the DAILY MAINTENANCE job. Without this patch,
retention is simply not configured for up to twenty-four hours after install,
and on a server whose port 22 is being scanned that is long enough to accumulate
a surprising number of rows before anything is set to clear them.
"""

import frappe


def execute():
	retentions = frappe.get_hooks("default_log_clearing_doctypes", app_name="server") or {}
	if not retentions:
		return

	settings = frappe.get_doc("Log Settings")
	for doctype, days in retentions.items():
		if not frappe.db.exists("DocType", doctype):
			continue
		# frappe stores hook values as lists; take the last, which is what
		# LogSettings.add_default_logtypes() does.
		retention = days[-1] if isinstance(days, list | tuple) else days
		settings.register_doctype(doctype, int(retention))
	settings.save(ignore_permissions=True)
