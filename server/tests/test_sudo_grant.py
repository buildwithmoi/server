# Copyright (c) 2026, Carbonite Solutions Ltd and contributors
# For license information, please see license.txt

"""The one thing this app cannot do for itself, asked for precisely.

certbot binds port 80 and writes to /etc/letsencrypt. This app runs as the
bench user — which is what makes it safe to give a web interface at all — so
there is no arrangement of code that gets a certificate without one sudoers
rule. What there was instead: a red cross saying "add a NOPASSWD sudoers rule
for this user", and an operator left to work out which commands.
"""

from __future__ import annotations

import inspect
import unittest

from server.bench import ssl


class TheProbeAsksAboutTheRightThing(unittest.TestCase):
	"""`sudo -n true` is the wrong question.

	It asks "can this user run ANYTHING as root", which a correctly narrow rule
	— NOPASSWD for certbot and nothing else — fails. So somebody who had done
	exactly the right thing was told to do it again, with the button still
	disabled and no way to tell the two states apart.
	"""

	def test_it_falls_back_to_asking_about_certbot(self):
		source = inspect.getsource(ssl.has_passwordless_sudo)
		self.assertIn('_run(["sudo", "-n", "true"]', source)
		self.assertIn("certbot", source)
		self.assertIn('"--version"', source)

	def test_version_is_chosen_because_it_touches_nothing(self):
		# Probing with a real certbot subcommand would issue or revoke
		# something to find out whether it could.
		self.assertIn("touches nothing", inspect.getsource(ssl.has_passwordless_sudo))


class TheSuggestedFile(unittest.TestCase):
	def setUp(self):
		self.text = ssl.sudoers_suggestion("erpnext", "/usr/bin/certbot", "/usr/local/bin/bench")

	def test_it_names_the_user_it_is_for(self):
		# Whoever reads this page is not necessarily whoever created the
		# account the app runs as.
		self.assertEqual(self.text.count("erpnext ALL=(root) NOPASSWD:"), 8)

	def test_it_grants_certbot_and_the_reload(self):
		self.assertIn("NOPASSWD: /usr/bin/certbot", self.text)
		self.assertIn("setup reload-nginx", self.text)

	def test_it_closes_the_four_detector_gaps_too(self):
		# sshd's effective config, password status, the firewall and the root
		# crontabs: each reports as unreadable rather than clean without these,
		# and "could not look" must never render the same as "nothing found".
		for command in ("/usr/sbin/sshd -T", "passwd -S -a", "ufw status verbose", "crontab -l -u root"):
			self.assertIn(command, self.text)

	def test_it_grants_nothing_broader(self):
		# No ALL=(ALL) ALL, no wildcards. A rule that grants everything is not
		# a narrower answer than no rule at all.
		self.assertNotIn("NOPASSWD: ALL", self.text)
		self.assertNotIn("*", self.text)

	def test_it_says_how_to_install_it(self):
		self.assertIn("visudo -f", self.text)
		self.assertIn(ssl.SUDOERS_PATH, self.text)


class OfferedOnlyWhenItWouldHelp(unittest.TestCase):
	def test_the_readiness_payload_carries_it(self):
		source = inspect.getsource(ssl.readiness)
		self.assertIn('"sudoers": "" if sudo_ok else sudoers_suggestion', source)

	def test_a_handled_check_is_not_drawn_as_a_failure(self):
		import pathlib

		view = (
			pathlib.Path(__file__).resolve().parents[2] / "serving" / "src" / "components" / "SslDialog.vue"
		).read_text()
		self.assertIn("check.blocking ? 'close' : 'play'", view)
		self.assertIn("done for you", view)


if __name__ == "__main__":
	unittest.main()
