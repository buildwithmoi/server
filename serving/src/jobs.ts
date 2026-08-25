/**
 * Tracking bench operations that are running right now.
 *
 * WHY A MODULE-LEVEL STORE AND NOT PER-PAGE STATE. A clone takes minutes, and
 * the whole point is that you can start one and go and look at something else.
 * State living inside the dialog or the Installs page dies the moment you
 * navigate, which is exactly when you most want to know the job is still going.
 * A module scope survives every route change in a SPA, so one poller serves the
 * dock, the sidebar indicator and any page that cares.
 *
 * Polling rather than a socket, deliberately: doppio's socket controller
 * hardcodes port 9000 while this bench runs socketio on 9008, and a poll is
 * also the only thing that gets the log right after a page reload — a socket
 * only ever carries what happened while you were listening.
 */

import { computed, ref } from "vue";
import { cancelInstallResource, installRequestResource, installRequestsResource } from "./api";

export interface JobStep {
	key: string;
	title: string;
	description: string;
	status: "Pending" | "Running" | "Success" | "Failure" | "Skipped";
	detail: string;
	output: string;
	started_at: string | null;
	finished_at: string | null;
	duration: number | null;
}

export interface Job {
	name: string;
	operation: string;
	app_name: string;
	bench: string;
	branch: string | null;
	status: string;
	exit_code: number | null;
	output: string;
	steps: JobStep[];
	command: string | null;
	error_summary: string | null;
	is_terminal: boolean;
	started_at: string | null;
	/** Fallback only, for the moment before the server's started_at arrives. */
	adoptedAt: number;
	/** True when several polls in a row have failed. The job is still tracked. */
	lostContact?: boolean;
}

const POLL_MS = 1500;

/** How long a finished job stays on screen so the outcome is actually seen. */
const LINGER_MS = 20000;

const jobs = ref<Record<string, Job>>({});

/** Consecutive failed polls per job, so a blip is not treated as a death. */
const lostContact = ref(new Map<string, number>());

/** Show "lost contact" only after this many consecutive failures. */
const LOST_CONTACT_AFTER = 3;
const expanded = ref<string | null>(null);
let timer: ReturnType<typeof setInterval> | null = null;

export const activeJobs = computed(() =>
	Object.values(jobs.value).filter((j) => !j.is_terminal),
);
export const finishedJobs = computed(() =>
	Object.values(jobs.value).filter((j) => j.is_terminal),
);
export const allJobs = computed(() =>
	Object.values(jobs.value).sort((a, b) => a.adoptedAt - b.adoptedAt),
);
export const isRunning = computed(() => activeJobs.value.length > 0);
export const expandedJob = computed(() => (expanded.value ? jobs.value[expanded.value] : null));

export function expand(name: string | null) {
	expanded.value = name;
}

export function dismiss(name: string) {
	const next = { ...jobs.value };
	delete next[name];
	jobs.value = next;
	if (expanded.value === name) expanded.value = null;
	if (!Object.keys(jobs.value).length) stopPolling();
}

/** Begin following a request. Safe to call twice for the same name. */
export function watchJob(name: string, seed: Partial<Job> = {}) {
	if (!jobs.value[name]) {
		jobs.value = {
			...jobs.value,
			[name]: {
				name,
				operation: seed.operation || "Clone",
				app_name: seed.app_name || "",
				bench: seed.bench || "",
				branch: seed.branch || null,
				status: seed.status || "Queued",
				exit_code: null,
				output: "",
				steps: [],
				command: null,
				error_summary: null,
				is_terminal: false,
				started_at: seed.started_at || null,
				adoptedAt: Date.now(),
			},
		};
	}
	startPolling();
	void refresh(name);
}

/**
 * Pick up anything already running — after a page reload, or a job someone
 * started in another tab. Without this, a refresh loses the dock entirely and
 * the operation appears to have stopped.
 */
export async function adoptRunningJobs() {
	const resource = installRequestsResource();
	try {
		const result = await resource.submit({ page_length: 20 });
		for (const row of result?.rows || []) {
			if (["Queued", "Running"].includes(row.status) && !jobs.value[row.name]) {
				watchJob(row.name, row);
			}
		}
	} catch {
		// A failure here means the dock stays empty, which is the same as before.
	}
}

async function refresh(name: string) {
	const job = jobs.value[name];
	if (!job) return;
	try {
		const data = await installRequestResource().submit({ name });
		jobs.value = { ...jobs.value, [name]: { ...job, ...data } };
		if (data.is_terminal) {
			// Leave the result up briefly rather than vanishing the instant it
			// finishes — a job that completes while you are on another page
			// would otherwise never be seen at all.
			setTimeout(() => {
				if (jobs.value[name]?.is_terminal && expanded.value !== name) dismiss(name);
			}, LINGER_MS);
		}
		lostContact.value.delete(name);
	} catch (err: any) {
		// A transient failure must not erase a running job.
		//
		// Dismissing on any error meant one 502 from a proxy, one worker
		// restart, or one refreshed session cookie removed the job from the
		// dock — which emptied activeJobs, which stopped the poller, so nothing
		// ever re-polled. A fifteen-minute clone vanished mid-flight with no
		// toast and no explanation, and the operator's only sign it was still
		// running was gone.
		const gone = err?.exc_type === "DoesNotExistError" || err?.httpStatus === 404;
		if (gone) {
			dismiss(name);
			return;
		}
		const failures = (lostContact.value.get(name) || 0) + 1;
		lostContact.value.set(name, failures);
		jobs.value = {
			...jobs.value,
			[name]: { ...job, lostContact: failures >= LOST_CONTACT_AFTER },
		};
	}
}

function startPolling() {
	if (timer) return;
	timer = setInterval(() => {
		const running = activeJobs.value;
		if (!running.length) {
			stopPolling();
			return;
		}
		running.forEach((job) => void refresh(job.name));
	}, POLL_MS);
}

function stopPolling() {
	if (timer) clearInterval(timer);
	timer = null;
}

/**
 * Elapsed seconds, counted from when the JOB started — not from when this
 * browser noticed it.
 *
 * Those differ badly. Reload the page twenty minutes into a clone and the
 * dock would restart at zero, which reads as "it just began" precisely when
 * you are checking whether it is stuck.
 */
export function elapsed(job: Job): number {
	const started = job.started_at ? Date.parse(job.started_at.replace(" ", "T")) : job.adoptedAt;
	const from = Number.isNaN(started) ? job.adoptedAt : started;
	return Math.max(0, Math.round((Date.now() - from) / 1000));
}

/** "8s", "4m 12s", "1h 03m" — readable at any duration. */
export function formatElapsed(seconds: number): string {
	if (seconds < 60) return `${seconds}s`;
	const m = Math.floor(seconds / 60);
	const s = seconds % 60;
	if (m < 60) return `${m}m ${String(s).padStart(2, "0")}s`;
	return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

/**
 * Ask a running job to stop.
 *
 * The worker owns the process, so this only raises a flag it polls — there is
 * nothing in the browser or the web process that could signal a subprocess in
 * another OS process. The status the poller reports next is the real answer.
 */
export async function cancelJob(name: string): Promise<string> {
	const job = jobs.value[name];
	if (job) job.status = "Cancelling";
	const result = await cancelInstallResource().submit({ name });
	return result?.message || "Stopping.";
}
