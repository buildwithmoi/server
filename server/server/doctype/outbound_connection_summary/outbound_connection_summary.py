# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Where this host connected out to, aggregated per destination per hour. Raw connections are far too many to keep and the aggregate is what gets investigated — 'this address, this port, this often' is the question anyone actually asks."""

from frappe.model.document import Document


class OutboundConnectionSummary(Document):
	pass
