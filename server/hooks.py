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
scheduler_events = {
	"cron": {
		# Five minutes bounds how stale the intrusion view can be. Reading a
		# cursor delta out of journald is milliseconds of work, so the cost is
		# the worker slot, not the query — and one-minute ticks would compete
		# for those slots with the bench operations this app also runs.
		"*/5 * * * *": ["server.ssh.ingest.enqueue_ingest"],
		# Offset by two minutes so a geolocation batch never starts in the same
		# tick as an ingest run.
		"2-59/5 * * * *": ["server.geo.registry.enqueue_resolve_pending"],
	},
	# "daily" is added together with the SSH Session doctype — a hook pointing at
	# a module that does not exist yet would create a Scheduled Job Type row that
	# fails every time it fires.
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
}

# Translation
# ------------
# List of apps whose translatable strings should be excluded from this app's translations.
# ignore_translatable_strings_from = []


website_route_rules = [
	{"from_route": "/serving/<path:app_path>", "to_route": "serving"},
]
