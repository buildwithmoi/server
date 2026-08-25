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

/* --------------------------------------------------------- bench commands */

export interface BenchCommandParam {
	name: string;
	label: string;
	placeholder: string;
	required: boolean;
}

export interface BenchCommandEntry {
	id: string;
	label: string;
	scope: "bench" | "site";
	description: string;
	risk: "read" | "routine" | "destructive" | "unsupported";
	runnable: boolean;
	unsupported_reason: string;
	preview: string;
	params: BenchCommandParam[];
}

export function benchCommandsResource() {
	return createResource({ url: `${M}.list_bench_commands` });
}

export function runBenchCommandResource() {
	return createResource({ url: `${M}.run_bench_command` });
}

/* ---------------------------------------------------------------------- ssl */

export interface SslCheck {
	key: string;
	label: string;
	ok: boolean;
	detail: string;
	blocking: boolean;
}

export interface SslSite {
	site: string;
	domain: string;
	is_default: boolean;
	has_cert: boolean;
	expires_on: string | null;
	days_left: number | null;
	note: string;
	custom_domains: string[];
	dns: {
		domain: string;
		resolved: string[];
		points_here: boolean;
		level: "ok" | "warn" | "danger";
		detail: string;
	};
}

export interface SslReadiness {
	bench: string;
	ready: boolean;
	checks: SslCheck[];
	sites: SslSite[];
	default_site: string | null;
	certificates_note: string;
}

export interface LogFile {
	name: string;
	path: string;
	scope: string;
	size: number;
	size_text: string;
	modified: number;
	modified_text: string;
	description: string;
	is_rotation: boolean;
}

export interface BackupCandidate {
	key: string;
	taken_at: string;
	size: number;
	size_text: string;
	age_hours: number;
	age_text: string;
	files: string[];
	deletable: boolean;
	reason: string;
}

export interface ConfigSetting {
	key: string;
	label: string;
	kind: "bool" | "int" | "string";
	description: string;
	disruptive: boolean;
	value: unknown;
	present: boolean;
	effective: unknown;
}

export function siteConfigResource() {
	return createResource({ url: `${M}.site_config` });
}

export function updateSiteConfigResource() {
	return createResource({ url: `${M}.update_site_config` });
}

export function backupPlanResource() {
	return createResource({ url: `${M}.backup_plan` });
}

export function pruneBackupsResource() {
	return createResource({ url: `${M}.prune_backups` });
}

export function logsResource() {
	return createResource({ url: `${M}.list_logs` });
}

export function readLogResource() {
	return createResource({ url: `${M}.read_log` });
}

export function cancelInstallResource() {
	return createResource({ url: `${M}.cancel_install_request` });
}

export interface AlertRow {
	name: string;
	subject: string;
	email_content: string;
	creation: string;
	read: number;
	document_type: string;
	document_name: string;
}

export function alertsResource() {
	return createResource({ url: `${M}.recent_alerts` });
}

export function markAlertsReadResource() {
	return createResource({ url: `${M}.mark_alerts_read` });
}

export function systemHealthResource() {
	return createResource({ url: `${M}.system_health` });
}

export function backupUsageResource() {
	return createResource({ url: `${M}.backup_usage` });
}

export function sslReadinessResource() {
	return createResource({ url: `${M}.ssl_readiness` });
}

export function runSslResource() {
	return createResource({ url: `${M}.run_ssl` });
}

/* ------------------------------------------------------------------ restore */

export interface BackupSet {
	key: string;
	site_slug: string;
	taken_at: string;
	database: string;
	public_files: string | null;
	private_files: string | null;
	site_config: string | null;
	size: number;
	size_text: string;
	encrypted: boolean;
	has_files: boolean;
	source: string;
	mismatch: string;
}

export interface SpaceEstimate {
	required: number;
	free: number;
	total: number;
	mountpoint: string;
	enough: boolean;
	detail: string;
}

export interface RestoreFile {
	path: string;
	name: string;
	directory: string;
	kind: string;
	size: number;
	size_text: string;
	modified: string;
	in_set: boolean;
	encrypted: boolean;
}

export interface BackupListing {
	site: string;
	bench_path: string;
	backups: (BackupSet & { space: SpaceEstimate })[];
	searched: string[];
}

export interface BackupApp {
	app_name: string;
	app_version: string;
	git_branch: string;
	present: boolean;
	branch_matches: boolean;
	installed_branch: string;
	note: string;
}

export interface BackupContents {
	apps: BackupApp[];
	missing: string[];
	bench_apps: string[];
	site_config_keys: string[];
	error: string;
	truncated: boolean;
}

export function inspectBackupResource() {
	return createResource({ url: `${M}.inspect_backup` });
}

/**
 * Upload a backup into the bench, in pieces.
 *
 * Not one request: frappe caps the body at 25 MB for every path except its own
 * upload endpoint, and reads the whole body into memory before the method
 * runs — so a single POST of a real dump was rejected with an HTML 413 that
 * the interface could only report as "Upload failed (413)". Pieces stay well
 * under the limit, hold nothing large in memory at either end, and give an
 * honest progress bar.
 */
const CHUNK_SIZE = 8 * 1024 * 1024;

export async function uploadBackup(
	bench: string,
	file: File,
	onProgress?: (percent: number) => void,
): Promise<{ name: string; path: string; size_text: string; directory: string }> {
	const total = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
	// Identifies this upload's part file on the server for its whole life.
	const uploadId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");

	let last: any = null;
	for (let index = 0; index < total; index += 1) {
		const slice = file.slice(index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE);
		const form = new FormData();
		form.append("file", slice, file.name);
		form.append("bench", bench);
		form.append("upload_id", uploadId);
		form.append("filename", file.name);
		form.append("chunk_index", String(index));
		form.append("total_chunks", String(total));

		const response = await fetch(`/api/method/${M}.upload_backup_chunk`, {
			method: "POST",
			headers: { "X-Frappe-CSRF-Token": (window as any).csrf_token || "" },
			body: form,
		});

		const text = await response.text();
		let payload: any = {};
		try {
			payload = JSON.parse(text);
		} catch {
			/* a non-JSON body means a proxy or the framework rejected it */
		}
		if (!response.ok || !payload.message) {
			// frappe returns its message as JSON inside JSON.
			let detail = payload.exception || `Upload failed (${response.status})`;
			try {
				const messages = JSON.parse(payload._server_messages || "[]");
				if (messages.length) detail = JSON.parse(messages[0]).message || detail;
			} catch {
				/* keep the fallback */
			}
			throw new Error(String(detail).replace(/<[^>]+>/g, ""));
		}

		last = payload.message;
		onProgress?.(Math.round(((index + 1) / total) * 100));
	}

	return last;
}

export function restoreFilesResource() {
	return createResource({ url: `${M}.list_restore_files` });
}

export function restoreSpaceResource() {
	return createResource({ url: `${M}.estimate_restore_space` });
}

export function backupsResource() {
	return createResource({ url: `${M}.list_backups` });
}

export function runRestoreResource() {
	return createResource({ url: `${M}.run_restore` });
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

/* --------------------------------------------------------- domain providers */

export function domainProvidersResource() {
	return createResource({ url: `${M}.list_domain_providers` });
}

export function saveDomainProviderResource() {
	return createResource({ url: `${M}.save_domain_provider` });
}

export function deleteDomainProviderResource() {
	return createResource({ url: `${M}.delete_domain_provider` });
}

export function verifyDomainProviderResource() {
	return createResource({ url: `${M}.verify_domain_provider` });
}

export function pointDomainResource() {
	return createResource({ url: `${M}.point_domain_at_this_host` });
}

export function domainReadinessResource() {
	return createResource({ url: `${M}.domain_readiness` });
}

export function runConsoleResource() {
	return createResource({ url: `${M}.run_console_command` });
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

/* ---------------------------------------------------------------- security */

export type Severity = "Critical" | "High" | "Medium" | "Info";

export interface SecurityEvent {
	name: string;
	event_time: string;
	severity: Severity;
	category: string;
	subject: string;
	detail: string;
	runbook: string;
	status: string;
	occurrences: number;
	last_seen: string | null;
	host: string;
	acknowledged_by: string | null;
	acknowledged_at: string | null;
	suppressed_until: string | null;
	suppression_reason: string | null;
	forwarded: 0 | 1;
	sequence: number | null;
}

export interface DetectorHeartbeat {
	source: string;
	last_run: string | null;
	sequence: number;
	last_status: string;
	expected_every: number;
}

export interface SshSession {
	name: string;
	session_key: string;
	status: "Open" | "Closed" | "Unknown";
	username: string;
	source_ip: string;
	country: string;
	auth_method: string;
	key_fingerprint: string;
	login_time: string;
	logout_time: string | null;
	duration: number;
	sudo_command_count: number;
	attribution_method: string;
	event_count: number;
	hostname: string;
	pid: number | null;
}

export function securityEventsResource() {
	return createResource({ url: `${M}.security_events` });
}

export function securityOverviewResource() {
	return createResource({ url: `${M}.security_overview` });
}

export function securityInventoryResource() {
	return createResource({ url: `${M}.security_inventory` });
}

export function acknowledgeEventResource() {
	return createResource({ url: `${M}.acknowledge_security_event` });
}

export function runSecurityScanResource() {
	return createResource({ url: `${M}.run_security_scan` });
}

export function acceptBaselineResource() {
	return createResource({ url: `${M}.accept_security_baseline` });
}

export function sshSessionsResource() {
	return createResource({ url: `${M}.ssh_sessions` });
}

export function sshSessionDetailResource() {
	return createResource({ url: `${M}.ssh_session_detail` });
}
