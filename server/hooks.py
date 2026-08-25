app_name = "server"
app_title = "Server"
app_publisher = "Carbonite Solutions Ltd"
app_description = "Managing the server and frappe benches "
app_email = "admin@carbonitesolutions.com"
app_license = "mit"

# Apps
# ------------------

# required_apps = []

# Each item in the list will be shown as an app in the apps page
# add_to_apps_screen = [
# 	{
# 		"name": "server",
# 		"logo": "/assets/server/logo.png",
# 		"title": "Server",
# 		"route": "/server",
# 		"has_permission": "server.api.permission.has_app_permission"
# 	}
# ]

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/server/css/server.css"
# app_include_js = "/assets/server/js/server.js"

# include js, css files in header of web template
# web_include_css = "/assets/server/css/server.css"
# web_include_js = "/assets/server/js/server.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "server/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
# doctype_js = {"doctype" : "public/js/doctype.js"}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Svg Icons
# ------------------
# include app icons in desk
# app_include_icons = "server/public/icons.svg"

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
# 	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# automatically load and sync documents of this doctype from downstream apps
# importable_doctypes = [doctype_1]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
# 	"methods": "server.utils.jinja_methods",
# 	"filters": "server.utils.jinja_filters"
# }

# Installation
# ------------

# before_install = "server.install.before_install"

# Verifies the machine can actually do the job — a readable authentication log,
# git, ssh, bench — and seeds the settings Single so its declared defaults are
# real stored values rather than load-time ones. Reports; never aborts.
after_install = "server.install.after_install"

# Uninstallation
# ------------

# before_uninstall = "server.uninstall.before_uninstall"
# after_uninstall = "server.uninstall.after_uninstall"

# Integration Setup
# ------------------
# To set up dependencies/integrations with other apps
# Name of the app being installed is passed as an argument

# before_app_install = "server.utils.before_app_install"
# after_app_install = "server.utils.after_app_install"

# Integration Cleanup
# -------------------
# To clean up dependencies/integrations with other apps
# Name of the app being uninstalled is passed as an argument

# before_app_uninstall = "server.utils.before_app_uninstall"
# after_app_uninstall = "server.utils.after_app_uninstall"

# Build
# ------------------
# To hook into the build process

# after_build = "server.build.after_build"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "server.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
# 	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
# 	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# Document Events
# ---------------
# Hook on document methods and events

# doc_events = {
# 	"*": {
# 		"on_update": "method",
# 		"on_cancel": "method",
# 		"on_trash": "method"
# 	}
# }

# Scheduled Tasks
# ---------------

# WHY `cron` IS SAFE HERE. Frappe skips non-daily scheduled jobs on "dormant"
# sites, which would quietly stop a low-traffic monitoring site from ingesting.
# It does not apply to us: `is_dormant()` returns False immediately unless
# `on_frappecloud()` is true, and that only matches sites whose domain ends in
# frappe.cloud / erpnext.com / frappehr.com / frappe.dev
# (frappe/utils/scheduler.py, frappe/utils/frappecloud.py). A self-hosted site
# is never dormant.
# Frappe skips a notification whose recipient is also its sender, which is
# reasonable for "X mentioned you" and wrong for a machine-generated alert. On a
# server whose only System Manager is Administrator — a fresh install, which is
# to say the case that matters most — every alert this app raises would have
# been silently dropped. "Alert" is precisely the type that has no human sender.
notification_self_notify_types = ["Alert"]

scheduler_events = {
	"cron": {
		# Five minutes bounds how stale the intrusion view can be. Reading a
		# cursor delta out of journald is milliseconds of work, so the cost is
		# the worker slot, not the query — and one-minute ticks would compete
		# for those slots with the bench operations this app also runs.
		"*/5 * * * *": ["server.ssh.ingest.enqueue_ingest"],
		# Offset by two minutes so a geolocation batch never starts in the same
		# tick as an ingest run.
		# NOTE: one entry per schedule string. This is a dict literal, so a
		# repeated key silently discards everything but the last value — which
		# is how `enqueue_resolve_pending` and `reap_stale_requests` both
		# stopped being scheduled at all without anything appearing to break.
		# `test_no_scheduler_slot_is_declared_twice` now fails on it.
		"2-59/5 * * * *": [
			"server.geo.registry.enqueue_resolve_pending",
			# Sockets and processes, offset from the SSH ingest so the two
			# never land on the same tick. This is the detector for the part
			# of the incident that had consequences — the proxying and the
			# outbound brute force that got the address blocked — and
			# connections are short-lived, so a slower cadence would miss them.
			"server.security.watch.run_network_scan",
		],
		# A worker can die between picking a job up and finishing it, and
		# nothing else notices: the row says Running forever, the dock spins,
		# and for a restore the database root password stays in the record
		# because the code that clears it never ran. Ten minutes is frequent
		# enough to matter and rare enough to cost nothing — the query is one
		# indexed range scan that almost always returns nothing.
		"*/10 * * * *": [
			"server.bench.installer.reap_stale_requests",
			# Watching the watcher, and pushing anything the collector missed.
			"server.security.watch.check_detectors_are_running",
			"server.security.forward.retry_pending",
		],
		# Intrusion sweeps run just after an ingest tick, so they read events
		# that were written moments ago rather than events from five minutes
		# before the ingest that would have found them.
		"4-59/5 * * * *": ["server.alerts.run_intrusion_checks"],
		# Disk moves slowly; hourly is plenty and keeps the alert rare enough
		# to still mean something when it arrives.
		"7 * * * *": ["server.alerts.run_disk_checks"],
		# The persistence surface, every fifteen minutes. Everything an
		# attacker uses to survive a reboot lives in a small, enumerable set of
		# places, and a clean host changes almost none of them — so the diff is
		# nearly all signal. The scan itself takes about three seconds.
		"*/15 * * * *": ["server.security.watch.run_persistence_scan"],
		# Accounts and keys, offset so the two scans never compete for the same
		# worker. Reading /etc/passwd is trivial; the cost is the dpkg lookups
		# the persistence scan does, and there is no reason to pay both at once.
		"5-59/15 * * * *": ["server.security.watch.run_account_scan"],
		# Setuid binaries, temp-directory droppers and world-writable system
		# files: 0.8 seconds measured, so it rides the ordinary schedule.
		# `dpkg --verify` is the expensive half and runs daily instead.
		"7-59/15 * * * *": [
			"server.security.watch.run_filesystem_scan",
			# What sshd is actually configured to do. This is the detector
			# aimed at the CAUSE of the incident rather than its symptoms —
			# the breached host accepted passwords, and everything else here
			# watches for what somebody does after getting in.
			"server.security.watch.run_sshd_scan",
		],
	},
	# Sessionising runs just after an ingest tick, so it reads events written
	# moments ago. It is idempotent — a second run over the same window
	# rewrites the same rows — which is what makes it safe on a schedule and
	# safe to run by hand while looking at something.
	"hourly": [
		"server.ssh.sessionize.enqueue_sessionize",
		# The application's own security state: credentials on disk, dangerous
		# settings, backup recency, who holds System Manager. Hourly rather
		# than quarter-hourly — these change when a person changes them, and
		# a backup going stale is measured in days.
		"server.security.watch.run_site_scan",
		# TLS, security headers, certificate expiry, and the set of endpoints
		# callable with no session. The last one is inventoried and diffed
		# rather than judged — fifty-five guest endpoints is how a web
		# framework works; a new one appearing is the finding.
		"server.security.watch.run_web_scan",
		# And this app watching itself: its own code, and whether its own
		# findings still add up. Editing the detector is cheaper than evading
		# it, and nothing else in the system notices when somebody does.
		"server.security.watch.run_self_scan",
	],
	"daily": [
		# One message a day saying what state this machine is in — including
		# on a quiet day, so that its ABSENCE means something. Immediate
		# alerting covers Critical and High and deliberately stops there; the
		# middle severities are batched here rather than either flooding a
		# mailbox or living only in a console nobody sits in front of.
		"server.security.digest.send",
		# `dpkg --verify` re-hashes every file every installed package owns:
		# 40 seconds of solid I/O here, against 0.8 for the rest of the
		# filesystem sweep. Daily is also the honest cadence for what it
		# finds — a replaced system binary does not put itself back while
		# nobody is watching, so catching it within the day loses nothing,
		# and re-reading the whole disk every quarter hour to be told
		# "still fine" costs a real server real throughput. Debian's own
		# debsums cron runs weekly.
		"server.security.watch.run_filesystem_deep_scan",
		# What software arrived or left, and what is waiting to be patched.
		# Daily: dpkg.log is a record of the past and does not become more
		# true for being read every quarter of an hour.
		"server.security.watch.run_package_scan",
	],

}

# Testing
# -------

# before_tests = "server.install.before_tests"

# Extend DocType Class
# ------------------------------
#
# Specify custom mixins to extend the standard doctype controller.
# extend_doctype_class = {
# 	"Task": "server.custom.task.CustomTaskMixin"
# }

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "server.event.get_events"
# }
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_dashboards = {
# 	"Task": "server.task.get_dashboard_data"
# }

# exempt linked doctypes from being automatically cancelled
#
# auto_cancel_exempted_doctypes = ["Auto Repeat"]

# Ignore links to specified DocTypes when deleting documents
# -----------------------------------------------------------

# ignore_links_on_delete = ["Communication", "ToDo"]

# Request Events
# ----------------
# before_request = ["server.utils.before_request"]
# after_request = ["server.utils.after_request"]

# Job Events
# ----------
# before_job = ["server.utils.before_job"]
# after_job = ["server.utils.after_job"]

# User Data Protection
# --------------------

# user_data_fields = [
# 	{
# 		"doctype": "{doctype_1}",
# 		"filter_by": "{filter_by}",
# 		"redact_fields": ["{field_1}", "{field_2}"],
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_2}",
# 		"filter_by": "{filter_by}",
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_3}",
# 		"strict": False,
# 	},
# 	{
# 		"doctype": "{doctype_4}"
# 	}
# ]

# Authentication and authorization
# --------------------------------

# auth_hooks = [
# 	"server.auth.validate"
# ]

# Automatically update python controller files with type annotations for this app.
# export_python_type_annotations = True

# Registers both log doctypes with frappe's Log Settings, which runs the daily
# clean-up. Registering here is only half of it: frappe will not clear a doctype
# unless its controller also implements a `clear_old_logs(days)` staticmethod
# (the LogType protocol in frappe/core/doctype/log_settings/log_settings.py).
#
# Auth events are high-volume and mostly scanner noise; sudo commands are
# low-volume and are the record you actually want when reconstructing what an
# intruder did. Hence the different retentions.
default_log_clearing_doctypes = {
	"SSH Auth Event": 90,
	"SSH Sudo Command": 180,
	# The conclusion outlives its evidence: sessions keep a year where the
	# events they were built from keep ninety days, because a session is what
	# someone reconstructing a months-old intrusion actually reads.
	"SSH Session": 365,
	# A year each. These are what you read when reconstructing a compromise
	# that ran for months — the incident behind this app went undetected for
	# eight — and they are small enough that keeping them costs nothing.
	"Security Event": 365,
	"Persistence Change": 365,
	"System Account Change": 365,
	# Aggregated per destination per hour, so ninety days of it is small — and
	# "when did this host start talking to that address" is the question worth
	# being able to answer months later.
	"Outbound Connection Summary": 90,
}

# Translation
# ------------
# List of apps whose translatable strings should be excluded from this app's translations.
# ignore_translatable_strings_from = []


website_route_rules = [
	{"from_route": "/serving/<path:app_path>", "to_route": "serving"},
]
