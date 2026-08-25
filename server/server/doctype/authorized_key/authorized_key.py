# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""One key that grants SSH access, by FINGERPRINT. The key material is never stored. The fingerprint is enough to say it is the same key as yesterday, and to join against the SSH login records, which already capture the fingerprint used on each login."""

from frappe.model.document import Document


class AuthorizedKey(Document):
	pass
