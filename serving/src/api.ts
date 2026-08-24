/**
 * Typed wrappers over the app's whitelisted endpoints.
 *
 * WHY NOT CALL frappe DIRECTLY FROM COMPONENTS. Every method name would then be
 * a string literal scattered across a dozen files, and renaming one on the
 * Python side would fail silently at runtime in whichever view nobody opened.
 * Collected here, the whole client/server contract is one file long and a
 * rename is one edit.
 */

import { createResource } from "frappe-ui";

const M = "server.api";

export type Outcome = "Success" | "Failure" | "Info";

export interface Totals {
	days: number;
	success: number;
	failure: number;
	info: number;
	total: number;
	attacking_ips: number;
	sudo_commands: number;
	sudo_denied: number;
}

export interface TimelinePoint {
	day: string;
	success: number;
	failure: number;
	info: number;
}

export interface CountryRow {
	country: string;
	total: number;
	success: number;
	failure: number;
}

export interface SourceRow {
	ip: string;
	attempts: number;
	successes: number;
	usernames: number;
	last_seen: string;
	country: string | null;
	city: string | null;
	isp: string | null;
	asn: string | null;
	geo_status: string | null;
}

export interface Checkpoint {
	source: string;
	last_run_at: string | null;
	last_run_status: string;
	records_inserted: number;
	records_skipped: number;
	records_unparsed: number;
	last_error: string | null;
}

export interface Health {
	monitoring_enabled: boolean;
	log_source: string | null;
	geo_enabled: boolean;
	pending_geolocation: number;
	checkpoints: Checkpoint[];
	fixture_rows: number;
}

export interface Overview {
	days: number;
	generated_at: string;
	totals: Totals;
	timeline: TimelinePoint[];
	by_country: CountryRow[];
	top_sources: SourceRow[];
	targeted_usernames: { username: string; attempts: number; invalid: number }[];
	recent_events: Record<string, unknown>[];
	recent_sudo: Record<string, unknown>[];
	health: Health;
}

/** The dashboard's single round trip. */
export function overviewResource(days = 7) {
	return createResource({
		url: `${M}.get_overview`,
		params: { days },
		cache: ["server-overview", days],
	});
}

export function authEventsResource() {
	return createResource({ url: `${M}.list_auth_events` });
}

export function sudoCommandsResource() {
	return createResource({ url: `${M}.list_sudo_commands` });
}

export function ipAddressesResource() {
	return createResource({ url: `${M}.list_ip_addresses` });
}

export function settingsResource() {
	return createResource({ url: `${M}.get_settings_summary` });
}

export function logSourceResource() {
	return createResource({ url: `${M}.check_log_source` });
}

/** What the reader has actually done — distinct from probing the machine. */
export function healthResource() {
	return createResource({ url: `${M}.get_health` });
}

/* ----------------------------------------------------------- github profiles */

export interface GitHubProfile {
	name: string;
	account: string;
	account_type: string;
	is_default: number;
	ssh_host_alias: string | null;
	has_token: boolean;
	repo_count: number;
	last_synced_at: string | null;
	sync_error: string | null;
}

export interface ProfileRepo {
	repo_name: string;
	default_branch: string | null;
	is_private: number;
	is_archived: number;
	description: string | null;
	pushed_at: string | null;
}

export function githubProfilesResource() {
	return createResource({ url: `${M}.list_github_profiles` });
}

export function saveGithubProfileResource() {
	return createResource({ url: `${M}.save_github_profile` });
}

export function deleteGithubProfileResource() {
	return createResource({ url: `${M}.delete_github_profile` });
}

export function syncGithubProfileResource() {
	return createResource({ url: `${M}.sync_github_profile` });
}

export function profileReposResource() {
	return createResource({ url: `${M}.list_profile_repos` });
}

export function repoBranchesResource() {
	return createResource({ url: `${M}.list_repo_branches` });
}

export function benchAppsResource() {
	return createResource({ url: `${M}.list_bench_apps` });
}

/* ------------------------------------------------------------------ benches */

export interface BenchApp {
	app_name: string;
	branch: string | null;
	commit: string | null;
	git_url: string | null;
	remote_name: string | null;
	is_shallow: number;
	is_dirty: number;
}

export interface Bench {
	name: string;
	bench_path: string;
	is_active: number;
	frappe_branch: string | null;
	python_version: string | null;
	webserver_port: number | null;
	socketio_port: number | null;
	default_site: string | null;
	shallow_clone: number;
	last_scanned_at: string | null;
	scan_error: string | null;
	apps: BenchApp[];
	sites: { site_name: string; is_default: number; installed_apps: string[] }[];
}

export function benchesResource() {
	return createResource({ url: `${M}.list_benches` });
}

export function benchResource() {
	return createResource({ url: `${M}.get_bench` });
}

export function rescanBenchesResource() {
	return createResource({ url: `${M}.rescan_benches` });
}

export function gitAuthResource() {
	return createResource({ url: `${M}.check_git_auth` });
}

export function installRequestsResource() {
	return createResource({ url: `${M}.list_install_requests` });
}

export function installRequestResource() {
	return createResource({ url: `${M}.get_install_request` });
}

export function createInstallResource() {
	return createResource({ url: `${M}.create_install_request` });
}

export function runInstallResource() {
	return createResource({ url: `${M}.run_install_request` });
}

export function checkRepoResource() {
	return createResource({ url: `${M}.check_repo_access` });
}

/* ----------------------------------------------------------------- actions */

export function setMonitoringResource() {
	return createResource({ url: `${M}.set_monitoring_enabled` });
}

export function runIngestResource() {
	return createResource({ url: `${M}.run_ingest_now` });
}

export function resolveGeoResource() {
	return createResource({ url: `${M}.resolve_geolocation` });
}

export function replayFixtureResource() {
	return createResource({ url: `${M}.replay_fixture` });
}

export function purgeFixturesResource() {
	return createResource({ url: `${M}.purge_fixture_events` });
}
