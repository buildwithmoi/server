# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""One port this host is listening on. Diffed against a baseline like the persistence surface: a bench opens its web, socketio and redis ports and nothing else, so a port that was not open at the last scan is worth reading."""

from frappe.model.document import Document


class ListeningSocket(Document):
	pass
