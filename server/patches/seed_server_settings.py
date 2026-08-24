# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Materialise Server Settings so its defaults are real stored values.

THE BUG THIS FIXES. A frappe Single stores only the fields that have actually
been written; `tabSingles` starts empty and the DocType's declared defaults are
applied at load time only while nothing has been saved. The moment ANY field is
written — a `db_set` from the dashboard toggle is enough — the document stops
being "new", defaults stop being applied, and every field nobody had touched
starts reading back as None.

That is not cosmetic. `geo_enabled` and `alerts_enabled` are declared with a
default of 1, and None is falsy: geolocation and alerting both switch themselves
off, silently, the first time an unrelated setting is changed. The dashboard
keeps working and simply stops resolving countries and stops raising alerts,
which on a security tool is the worst way to fail.

WHY "IS IT SET" IS ANSWERED FROM tabSingles, NOT FROM THE LOADED DOCUMENT. An
unset Check reads back as 0, which is indistinguishable from an operator having
deliberately switched it off. Asking the table whether a row exists at all is
the only test that separates "never configured" from "configured to off" — and
getting that wrong writes 0 over a declared default of 1, which is exactly the
failure this patch exists to prevent.

Idempotent: a field already present in tabSingles is never touched.
"""

import frappe

DOCTYPE = "Server Settings"


def execute():
	if not frappe.db.exists("DocType", DOCTYPE):
		return

	# Snapshot BEFORE loading the document — saving it would create rows for
	# every field and destroy the distinction we depend on.
	stored = {
		row.field
		for row in frappe.db.sql(
			"SELECT field FROM tabSingles WHERE doctype = %(doctype)s", {"doctype": DOCTYPE}, as_dict=True
		)
	}

	meta = frappe.get_meta(DOCTYPE)
	pending = {}
	for field in meta.fields:
		if field.fieldtype in frappe.model.no_value_fields:
			continue
		if field.default in (None, ""):
			continue
		if field.fieldname in stored:
			continue
		pending[field.fieldname] = (
			int(field.default) if field.fieldtype in ("Check", "Int") else field.default
		)

	if not pending:
		return

	settings = frappe.get_single(DOCTYPE)
	for fieldname, value in pending.items():
		settings.set(fieldname, value)
	settings.flags.ignore_permissions = True
	settings.save()
	frappe.db.commit()
	print(f"Server Settings: persisted defaults for {', '.join(sorted(pending))}")
