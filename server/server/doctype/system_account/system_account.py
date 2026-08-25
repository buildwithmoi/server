# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""One account that exists on this host. Current state; changes are in System Account Change. Password HASHES are never recorded — only whether a password is set, locked or absent, because an app that watches for compromise must not become the richest target on the estate."""

from frappe.model.document import Document


class SystemAccount(Document):
	pass
