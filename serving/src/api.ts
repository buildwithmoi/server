/**
 * Typed wrappers over the app's whitelisted endpoints.
 *
 * WHY NOT CALL frappe DIRECTLY FROM COMPONENTS. Every method name would then be
 * a string literal scattered across a dozen files, and renaming one on the
 * Python side would fail silently at runtime in whichever view nobody opened.
 * Collected here, the whole client/server contract is one file long and a
 * rename is one edit.
 */

import { reactive, ref } from "vue";
import { createResource } from "frappe-ui";

import { currentServer } from "./serverSwitch";

const M = "server.api";

/**
 * A resource that follows the server switch.
 *
 * WHY NOT `createResource`. frappe-ui fixes a resource's URL when it is
 * created, and the switch happens long afterwards — so a resource built for
 * `list_benches` cannot later decide to go through `call_remote` instead.
 * `makeParams` can rewrite the arguments and `transform` the answer, but
 * neither can change where the call goes.
 *
 * So this is a small hand-rolled equivalent exposing the same four things the
 * views use — `data`, `loading`, `submit`, `fetch` — which is why switching
 * required no change to any view. `uploadBackup` below bypasses
 * `createResource` for the same kind of reason.
 *
 * WHEN NO SERVER IS SELECTED it calls the method directly, so the local path
 * is exactly what it was before this existed.
 */
export function switchable(method: string) {
	const data = ref<any>(null);
	const loading = ref(false);
	const error = ref<any>(null);

	async function run(args: Record<string, any> = {}) {
		loading.value = true;
		error.value = null;
		try {
			const server = currentServer.value;
			const payload = server
				? { url: `${M}.call_remote`, body: { server, method: `${M}.${method}`, args } }
				: { url: `${M}.${method}`, body: args };

			const response = await fetch(`/api/method/${payload.url}`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"X-Frappe-CSRF-Token": (window as any).csrf_token,
				},
				body: JSON.stringify(payload.body),
			});

			const text = await response.text();
			let parsed: any = {};
			try {
				parsed = text ? JSON.parse(text) : {};
			} catch {
				throw new Error(`${method} returned something that is not JSON`);
			}

			if (!response.ok) throw asError(parsed, response.status);

			// Unwrap frappe's `message`, then the proxy's own envelope — a view
			// asking for benches should get benches whichever route it took.
			const message = parsed.message ?? parsed;
			data.value = server && message && typeof message === "object" && "message" in message
				? message.message
				: message;
			return data.value;
		} catch (caught) {
			error.value = caught;
			throw caught;
		} finally {
			loading.value = false;
		}
	}

	return reactive({ data, loading, error, submit: run, fetch: run, reset: () => (data.value = null) });
}

/** frappe reports errors in `_server_messages`, double-encoded and in HTML. */
function asError(parsed: any, status: number) {
	let text = "";
	try {
		const messages = JSON.parse(parsed._server_messages || "[]");
		text = messages.map((m: string) => JSON.parse(m).message || m).join(" ");
	} catch {
		text = parsed.exception || parsed.message || "";
	}
	const error: any = new Error(String(text || `Request failed (${status})`).replace(/<[^>]+>/g, ""));
	error.messages = [error.message];
	return error;
}

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
	return switchable("list_auth_events");
}

export function sudoCommandsResource() {
	return switchable("list_sudo_commands");
}

export function ipAddressesResource() {
	return switchable("list_ip_addresses");
}

export function settingsFormResource() {
	return switchable("server_settings_form");
}

export function saveSettingsResource() {
	return switchable("save_server_settings");
}

export function settingsResource() {
	return switchable("get_settings_summary");
}

export function logSourceResource() {
	return switchable("check_log_source");
}

/** What the reader has actually done — distinct from probing the machine. */
export function healthResource() {
	return switchable("get_health");
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
	return switchable("list_github_profiles");
}

export function saveGithubProfileResource() {
	return switchable("save_github_profile");
}

export function deleteGithubProfileResource() {
	return switchable("delete_github_profile");
}

export function syncGithubProfileResource() {
	return switchable("sync_github_profile");
}

export function profileReposResource() {
	return switchable("list_profile_repos");
}

export function repoBranchesResource() {
	return switchable("list_repo_branches");
}

export function benchAppsResource() {
	return switchable("list_bench_apps");
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
	return switchable("list_bench_commands");
}

export function runBenchCommandResource() {
	return switchable("run_bench_command");
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
	return switchable("site_config");
}

export function updateSiteConfigResource() {
	return switchable("update_site_config");
}

export function backupPlanResource() {
	return switchable("backup_plan");
}

export function pruneBackupsResource() {
	return switchable("prune_backups");
}

export function logsResource() {
	return switchable("list_logs");
}

export function readLogResource() {
	return switchable("read_log");
}

export function cancelInstallResource() {
	return switchable("cancel_install_request");
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
	return switchable("recent_alerts");
}

export function markAlertsReadResource() {
	return switchable("mark_alerts_read");
}

export function systemHealthResource() {
	return switchable("system_health");
}

export function backupUsageResource() {
	return switchable("backup_usage");
}

export function sslReadinessResource() {
	return switchable("ssl_readiness");
}

export function runSslResource() {
	return switchable("run_ssl");
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
	return switchable("inspect_backup");
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
	return switchable("list_restore_files");
}

export function restoreSpaceResource() {
	return switchable("estimate_restore_space");
}

export function backupsResource() {
	return switchable("list_backups");
}

export function runRestoreResource() {
	return switchable("run_restore");
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
	return switchable("list_benches");
}

export function benchResource() {
	return switchable("get_bench");
}

export function rescanBenchesResource() {
	return switchable("rescan_benches");
}

export function gitAuthResource() {
	return switchable("check_git_auth");
}

export function installRequestsResource() {
	return switchable("list_install_requests");
}

export function installRequestResource() {
	return switchable("get_install_request");
}

export function createInstallResource() {
	return switchable("create_install_request");
}

export function runInstallResource() {
	return switchable("run_install_request");
}

/* ------------------------------------------------------------- provisioning */

export function provisionPreflightResource() {
	return switchable("provision_preflight");
}

export function runProvisionResource() {
	return switchable("run_provision");
}

/* --------------------------------------------------------- domain providers */

export function domainProvidersResource() {
	return switchable("list_domain_providers");
}

export function saveDomainProviderResource() {
	return switchable("save_domain_provider");
}

export function deleteDomainProviderResource() {
	return switchable("delete_domain_provider");
}

export function verifyDomainProviderResource() {
	return switchable("verify_domain_provider");
}

export function pointDomainResource() {
	return switchable("point_domain_at_this_host");
}

export function domainReadinessResource() {
	return switchable("domain_readiness");
}

export function runConsoleResource() {
	return switchable("run_console_command");
}

export function checkRepoResource() {
	return switchable("check_repo_access");
}

/* ----------------------------------------------------------------- actions */

export function setMonitoringResource() {
	return switchable("set_monitoring_enabled");
}

export function readHistoryResource() {
	return switchable("read_history");
}

export function runIngestResource() {
	return switchable("run_ingest_now");
}

export function resolveGeoResource() {
	return switchable("resolve_geolocation");
}

export function replayFixtureResource() {
	return switchable("replay_fixture");
}

export function purgeFixturesResource() {
	return switchable("purge_fixture_events");
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
	return switchable("security_events");
}

export function securityOverviewResource() {
	return switchable("security_overview");
}

export function securityInventoryResource() {
	return switchable("security_inventory");
}

export function acknowledgeEventResource() {
	return switchable("acknowledge_security_event");
}

export function runSecurityScanResource() {
	return switchable("run_security_scan");
}

export function acceptBaselineResource() {
	return switchable("accept_security_baseline");
}

export function sshSessionsResource() {
	return switchable("ssh_sessions");
}

export function sshSessionDetailResource() {
	return switchable("ssh_session_detail");
}

/* ------------------------------------------------------------------- logs */

export function jobLogsResource() {
	return switchable("job_logs");
}

export function jobLogResource() {
	return switchable("job_log");
}

/* ---------------------------------------------------------------- servers */

export interface ManagedServer {
	name: string;
	server_name: string;
	base_url: string;
	is_this_server: 0 | 1;
	verify_tls: 0 | 1;
	status: "Unverified" | "Reachable" | "Unreachable" | "Refused";
	last_verified_at: string | null;
	remote_hostname: string;
	remote_version: string;
	verify_error: string;
	api_key: string;
	has_secret: boolean;
}

export function managedServersResource() {
	return switchable("list_managed_servers");
}

export function saveManagedServerResource() {
	return switchable("save_managed_server");
}

export function deleteManagedServerResource() {
	return switchable("delete_managed_server");
}

export function verifyManagedServerResource() {
	return switchable("verify_managed_server");
}

export function callRemoteResource() {
	return switchable("call_remote");
}

export function remoteReadinessResource() {
	return switchable("remote_site_readiness");
}

/* ------------------------------------------------------------- migrations */

export function planMigrationResource() {
	return switchable("plan_bench_migration");
}

export function startMigrationResource() {
	return switchable("start_bench_migration");
}

export function migrationResource() {
	return switchable("bench_migration");
}

export function resumeMigrationResource() {
	return switchable("resume_bench_migration");
}

export function cancelMigrationResource() {
	return switchable("cancel_bench_migration");
}

export function dnsRecordsResource() {
	return switchable("dns_records");
}

export function saveDnsRecordResource() {
	return switchable("save_dns_record");
}

export function deleteDnsRecordResource() {
	return switchable("delete_dns_record");
}

export function benchMigrationsResource() {
	return switchable("list_bench_migrations");
}

export function benchRootReportResource() {
	return switchable("bench_root_report");
}

export function scheduledLogsResource() {
	return switchable("scheduled_logs");
}

export function crashLogsResource() {
	return switchable("crash_logs");
}

export function crashLogResource() {
	return switchable("crash_log");
}
