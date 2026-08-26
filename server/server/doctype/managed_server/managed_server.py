# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""Another machine running this app, and the credentials to reach it.

THE RISK THIS DOCTYPE CREATES, stated plainly because the rest of this app is
built around not creating it. Every other secret here is scoped to one job: a
database password used for one restore and cleared afterwards, a DNS token
that can only edit DNS. An API secret for another server is different — it
grants everything this app can do, on that machine, for as long as it exists.
A console holding three of them is a console worth breaking into.

Three things make that a considered trade rather than an oversight:

  * the secret is a `Password` field, so it lives encrypted in `__Auth` and is
    never returned to the browser — the switcher only ever learns that a key
    exists, not what it is;
  * the remote should be given its OWN user, not a person's, so it can be
    revoked without locking anybody out;
  * every mutating call made through the proxy is recorded as a Security
    Event, on this server, naming the operator and the remote.

The alternative was pointing the browser straight at each machine, which needs
CORS opened on all of them and puts the same secret into JavaScript. This is
the smaller hole.
"""

import frappe
from frappe.model.document import Document


class ManagedServer(Document):
	def validate(self):
		self.base_url = (self.base_url or "").strip().rstrip("/")
		if self.base_url and not self.base_url.startswith(("http://", "https://")):
			frappe.throw(
				f"{self.base_url!r} needs a scheme — https://host, or http://host on a private "
				"network you trust.",
				title="Address Is Not A URL",
			)
		if self.base_url.startswith("http://") and not self.is_this_server:
			# Not refused: a private network with no TLS is a real situation.
			# Said out loud because the thing being carried is a database.
			frappe.msgprint(
				"This address is plain HTTP, so the API secret and any backup pulled through it "
				"cross the network in the clear.",
				title="Not Encrypted",
				indicator="orange",
			)
		self._enforce_single_local()

	def _enforce_single_local(self):
		"""Exactly one row may be the local machine.

		Two would make "switch back to local" ambiguous, and the switcher uses
		it to decide when NOT to make a network call at all.
		"""
		if not self.is_this_server:
			return
		others = frappe.get_all(
			"Managed Server", filters={"is_this_server": 1, "name": ["!=", self.name]}, pluck="name"
		)
		for other in others:
			frappe.db.set_value("Managed Server", other, "is_this_server", 0, update_modified=False)

	def get_secret(self) -> str:
		return self.get_password("api_secret", raise_exception=False) or ""

	def client(self):
		"""A ready-to-use client, or a throw explaining what is missing."""
		from server.remote.client import RemoteServer

		if self.is_this_server:
			frappe.throw(
				f"{self.name} is this machine — there is nothing to call over the network.",
				title="Local Server",
			)
		if not self.api_key or not self.get_secret():
			frappe.throw(
				f"{self.name} has no API key and secret, so this server cannot talk to it.",
				title="No Credentials",
			)
		return RemoteServer(
			base_url=self.base_url,
			api_key=self.api_key,
			api_secret=self.get_secret(),
			verify_tls=bool(self.verify_tls),
		)

	def record_check(self, ok: bool, error: str = "", identity: dict | None = None) -> None:
		"""Store the outcome of a reachability check without touching modified."""
		identity = identity or {}
		self.db_set(
			{
				"status": "Reachable" if ok else ("Refused" if "refused" in error.lower() else "Unreachable"),
				"last_verified_at": frappe.utils.now_datetime(),
				"verify_error": "" if ok else error[:500],
				"remote_hostname": identity.get("hostname") or self.remote_hostname,
				"remote_version": identity.get("version") or self.remote_version,
			},
			update_modified=False,
		)
