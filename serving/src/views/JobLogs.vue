<template>
	<AppShell :title="label" :subtitle="subtitle">
		<template #actions>
			<select v-model="status" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" @change="reload(0)">
				<option value="">All runs</option>
				<option value="Success">Succeeded</option>
				<option value="Failed">Failed</option>
				<option value="Running">Running</option>
			</select>
		</template>

		<p class="mb-4 text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			{{ blurb }} Open one to read the whole transcript, or copy it out to send on —
			it carries the commands, the timings and the full output, with nothing trimmed.
		</p>

		<!--
			A run opened by name that is not in the list on screen — because it
			is older than this page, or the status filter excludes it. Without
			this the panel is attached to a row that is not there, and clicking
			a failed step showed nothing at all.
		-->
		<div v-if="detachedLog" class="mb-4 rounded-lg border border-[var(--ink)] bg-[var(--paper)] p-3">
			<div class="mb-3 flex flex-wrap items-center gap-2">
				<OutcomeMark
					:outcome="outcomeOf(detachedLog.request?.status)"
					:label="detachedLog.request?.status || ''"
				/>
				<span class="u-mono text-[13px]">
					{{ detachedLog.request?.app_name || detachedLog.request?.name }}
				</span>
				<span class="text-[11.5px] text-[var(--ink-faint)]">
					{{ detachedLog.request?.operation }}
				</span>
				<Button variant="subtle" class="ml-auto" @click="copy">
					<template #prefix><Icon name="copy" :size="13" /></template>
					{{ copied ? "Copied" : "Copy the whole log" }}
				</Button>
				<Button variant="ghost" @click="download">
					<template #prefix><Icon name="download" :size="13" /></template>
					Download
				</Button>
			</div>
			<JobSteps v-if="detachedLog.steps?.length" :steps="detachedLog.steps" class="mb-3" />
			<pre class="u-term u-scroll max-h-[26rem] overflow-auto rounded-lg p-3 text-[12px] leading-[1.5]">{{ detachedLog.transcript }}</pre>
		</div>

		<div v-if="loading && !rows.length" class="space-y-2">
			<Skeleton v-for="n in 5" :key="n" class="h-14" />
		</div>

		<EmptyState v-else-if="!rows.length" :title="emptyTitle" :hint="emptyHint" />

		<ul v-else class="u-scroll max-h-[calc(100vh-17rem)] space-y-2 overflow-y-auto pr-1">
			<li
				v-for="row in rows"
				:key="row.name"
				class="rounded-lg border border-[var(--rule)] bg-[var(--paper)] transition-colors hover:border-[var(--rule-strong)]"
			>
				<button type="button" class="flex w-full items-start gap-3 p-3 text-left" @click="toggle(row)">
					<OutcomeMark :outcome="outcomeOf(row.status)" :label="row.status" class="mt-[2px]" />
					<div class="min-w-0 flex-1">
						<p class="text-[13.5px]">
							<span class="u-mono">{{ headline(row) }}</span>
							<span v-if="row.restore_remote_server" class="text-[var(--ink-faint)]">
								← <span class="u-mono">{{ row.restore_remote_site }}</span>
								on {{ row.restore_remote_server }}
							</span>
						</p>
						<p class="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11.5px] text-[var(--ink-faint)]">
							<!-- Who and when lead, because a log nobody watched
							     always raises those two first. -->
							<span>{{ row.owner }}</span>
							<span>{{ when(row.started_at || row.creation) }}</span>
							<span v-if="row.duration">took {{ took(row.duration) }}</span>
							<span v-if="row.provision_frappe_version" class="u-mono">v{{ row.provision_frappe_version }}</span>
							<span v-if="row.restore_source" class="u-mono">{{ row.restore_source.toLowerCase() }}</span>
						</p>
						<p v-if="row.error_summary" class="mt-1 text-[12px] text-[var(--danger)]">
							{{ row.error_summary }}
						</p>
					</div>
					<Icon
						name="chevron"
						:size="13"
						class="mt-1.5 shrink-0 text-[var(--ink-ghost)] transition-transform duration-200"
						:class="opened === row.name ? '-rotate-90' : 'rotate-90'"
					/>
				</button>

				<div v-if="opened === row.name" class="border-t border-[var(--rule)] p-3">
					<div v-if="detail.loading" class="space-y-2">
						<Skeleton v-for="n in 4" :key="n" class="h-4" />
					</div>

					<template v-else-if="log">
						<div class="mb-3 flex flex-wrap items-center gap-2">
							<Button variant="subtle" @click="copy">
								<template #prefix><Icon name="copy" :size="13" /></template>
								{{ copied ? "Copied" : "Copy the whole log" }}
							</Button>
							<Button variant="ghost" @click="download">
								<template #prefix><Icon name="download" :size="13" /></template>
								Download
							</Button>
							<span class="text-[11.5px] text-[var(--ink-faint)]">
								{{ lineCount }} lines · {{ log.filename }}
							</span>
						</div>

						<JobSteps v-if="log.steps?.length" :steps="log.steps" class="mb-3" />

						<!--
							The transcript exactly as the copy button and the
							download produce it. A log that reads differently
							depending on how you obtained it is one nobody can
							compare against another.
						-->
						<pre class="u-term u-scroll max-h-[26rem] overflow-auto rounded-lg p-3 text-[12px] leading-[1.5]">{{ log.transcript }}</pre>
					</template>
				</div>
			</li>
		</ul>

		<div v-if="total > rows.length" class="mt-4 flex justify-center">
			<Button variant="subtle" :loading="loading" @click="reload(start + PAGE)">Show older runs</Button>
		</div>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import JobSteps from "../components/JobSteps.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import Skeleton from "../components/Skeleton.vue";
import { jobLogResource, jobLogsResource } from "../api";

const PAGE = 50;

const props = defineProps({
	// "deployment" or "restore". The two pages differ only in which operation
	// they list and how a row is titled; everything else — the transcript, the
	// copy, the download — is deliberately identical.
	kind: { type: String, default: "deployment" },
});

const resource = jobLogsResource();
const detail = jobLogResource();

const label = computed(() => resource.data?.label || (props.kind === "restore" ? "Bench Restoration" : "Bench Deployment"));

const blurb = computed(() =>
	props.kind === "restore"
		? "Every site restore, including sites pulled from another server."
		: "Every bench build, with the commands it ran and what they said.",
);

const emptyTitle = computed(() =>
	props.kind === "restore" ? "No restores yet" : "No deployments yet",
);
const emptyHint = computed(() =>
	props.kind === "restore"
		? "Restoring a site from a bench, from uploaded files, or from another server records the whole run here."
		: "Building a bench from the Benches page records the whole run here.",
);

/** What to call a row: the bench being built, or the site being restored. */
function headline(row) {
	return row.provision_bench_name || row.install_on_site || row.bench || "—";
}

const start = ref(0);
const status = ref("");
const route = useRoute();
const opened = ref("");
const copied = ref(false);

const rows = computed(() => resource.data?.rows || []);
const total = computed(() => resource.data?.total || 0);
const loading = computed(() => resource.loading);
const log = computed(() => detail.data);
const lineCount = computed(() => (log.value?.transcript || "").split("\n").length);

/** The opened run, when it is not one of the rows currently listed. */
const detachedLog = computed(() => {
	if (!opened.value || !log.value) return null;
	return rows.value.some((r) => r.name === opened.value) ? null : log.value;
});

const subtitle = computed(() => {
	if (loading.value && !rows.value.length) return "loading…";
	const failed = resource.data?.by_status?.Failed || 0;
	if (failed) return `${total.value} runs · ${failed} failed`;
	return total.value ? `${total.value} runs` : "none yet";
});

const OUTCOMES = { Success: "Success", "Completed With Warnings": "Info", Failed: "Failure" };
const outcomeOf = (s) => OUTCOMES[s] || "Info";

function when(value) {
	if (!value) return "";
	const date = new Date(value.replace(" ", "T"));
	return Number.isNaN(date.getTime())
		? value
		: date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function took(seconds) {
	const total = Math.round(Number(seconds) || 0);
	if (total < 60) return `${total}s`;
	const minutes = Math.floor(total / 60);
	return minutes < 60 ? `${minutes}m ${String(total % 60).padStart(2, "0")}s` : `${(total / 3600).toFixed(1)}h`;
}

function toggle(row) {
	copied.value = false;
	if (opened.value === row.name) {
		opened.value = "";
		return;
	}
	opened.value = row.name;
	detail.submit({ name: row.name }).catch((error) => {
		toast.error(error.messages?.[0] || "Could not read that log");
	});
}

async function copy() {
	try {
		await navigator.clipboard.writeText(log.value.transcript);
		copied.value = true;
		setTimeout(() => (copied.value = false), 2000);
	} catch {
		// Clipboard access is refused outside a secure context, which is
		// exactly where this app runs before anyone has set up TLS. Falling
		// back to a download means the button still achieves something.
		download();
		toast.info("Copying was blocked, so it downloaded instead.");
	}
}

function download() {
	const blob = new Blob([log.value.transcript], { type: "text/plain;charset=utf-8" });
	const url = URL.createObjectURL(blob);
	const link = document.createElement("a");
	link.href = url;
	link.download = log.value.filename;
	link.click();
	URL.revokeObjectURL(url);
}

function reload(nextStart = 0) {
	start.value = nextStart;
	return resource
		.submit({ kind: props.kind, start: nextStart, page_length: PAGE, status: status.value || null })
		.catch((error) => toast.error(error.messages?.[0] || "Could not load the deployments"));
}

/**
 * Arriving with ?job=<name> opens that one straight away.
 *
 * Clicking a failed step used to land on a list and leave you to find the run
 * yourself — and if it was not the newest, or the status filter excluded it,
 * there was nothing on screen at all.
 */
async function openRequested() {
	const wanted = route.query.job;
	if (!wanted) return;
	const row = rows.value.find((r) => r.name === wanted);
	if (row) {
		toggle(row);
		return;
	}
	// Not on this page of results. Read it directly rather than paging
	// backwards through a list looking for it.
	opened.value = String(wanted);
	detail.submit({ name: wanted }).catch(() => {
		toast.error("That run is not in this log — it may belong to another kind of job.");
		opened.value = "";
	});
}

onMounted(async () => {
	await reload(0);
	openRequested();
});
</script>
