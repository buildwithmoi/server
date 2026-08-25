<template>
	<AppShell title="App Installs" :subtitle="subtitle">
		<template #actions>
			<Button variant="solid" @click="showForm = !showForm">
				<template #prefix><Icon name="download" :size="14" /></template>
				{{ showForm ? "Close" : "New install" }}
			</Button>
		</template>

		<!-- The interlock is stated up front rather than discovered on submit. -->
		<div
			v-if="settings.data && !settings.data.allow_app_install"
			class="mb-3 flex items-start gap-3 rounded-lg border border-[var(--ink)] bg-[var(--paper-sunk)] px-4 py-3"
		>
			<Icon name="alert" :size="17" class="mt-0.5 shrink-0" />
			<div class="min-w-0 flex-1">
				<p class="text-[13px] font-medium">App installs are switched off</p>
				<p class="mt-0.5 text-[12.5px] leading-relaxed text-[var(--ink-soft)]">
					Nothing here will run a bench command until Allow App Installs is enabled in
					Server Settings. It is off by default so this app cannot execute anything on the
					host until you deliberately arm it.
				</p>
			</div>
			<a :href="deskSettings" class="shrink-0 text-[12.5px] underline underline-offset-2">Open settings</a>
		</div>

		<!--
			One install form, not two.

			This page used to carry its own, with a hardcoded Organisation
			dropdown that sent `github_org` — a field no endpoint accepts. Frappe
			stripped it, `github_profile` was never sent, and every submit failed
			with a message naming a control this form did not have. The bench
			page's dialog builds a correct payload from the GitHub Profile
			records, so this opens that instead of maintaining a second one.
		-->
		<Transition
			enter-active-class="transition-all duration-250 ease-[var(--ease)]"
			enter-from-class="opacity-0 -translate-y-2"
			leave-active-class="transition-all duration-150 ease-[var(--ease)]"
			leave-to-class="opacity-0 -translate-y-2"
		>
			<div v-if="showForm" class="u-card mb-3 flex flex-wrap items-end gap-3 p-4">
				<label class="flex min-w-[220px] flex-1 flex-col gap-1.5">
					<span class="u-label">Bench</span>
					<select
						v-model="chosenBench"
						class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
					>
						<option value="" disabled>choose a bench</option>
						<option v-for="b in benchOptions" :key="b.name" :value="b.name">{{ b.name }}</option>
					</select>
				</label>

				<Button variant="solid" :disabled="!chosenBench || !allowed" @click="showInstall = true">
					<template #prefix><Icon name="download" :size="14" /></template>
					Install an app…
				</Button>
				<Button :disabled="!chosenBench || !allowed" @click="openPull">
					<template #prefix><Icon name="refresh" :size="14" /></template>
					Update an app…
				</Button>

				<p class="u-item-detail min-w-[200px] flex-1">
					Opens the same dialog as the bench page: pick a GitHub account, then search its
					repositories and branches.
				</p>
			</div>
		</Transition>

		<InstallDialog
			v-if="chosenBench"
			v-model="showInstall"
			:bench="chosenBench"
			:sites="sitesFor(chosenBench)"
			:initial-operation="installMode"
			@started="onStarted"
		/>

		<section v-if="active" class="u-card mb-3 overflow-hidden">
			<header class="flex items-center justify-between gap-3 border-b border-[var(--rule)] px-4 py-3">
				<div class="flex min-w-0 items-center gap-2.5">
					<Spinner v-if="!active.is_terminal" class="h-3.5 w-3.5 shrink-0" />
					<OutcomeMark v-else :outcome="['Success', 'Completed With Warnings'].includes(active.status) ? 'Success' : 'Failure'" :label="active.status" />
					<span class="u-mono truncate text-[13px]">{{ active.name }} · {{ active.app_name }}</span>
				</div>
				<button class="text-[12px] text-[var(--ink-faint)] hover:text-[var(--ink)]" @click="active = null">
					Close
				</button>
			</header>

			<p v-if="active.command" class="u-mono border-b border-[var(--rule)] bg-[var(--paper-sunk)] px-4 py-2 text-[11.5px] text-[var(--ink-soft)]">
				$ {{ active.command }}
			</p>

			<!-- Steps, then the raw log underneath for anyone who wants all of
			     it. The step list answers "what happened"; the log answers
			     "exactly what was printed", and both are worth having. -->
			<div v-if="active.steps?.length" class="px-4 py-3">
				<JobSteps :steps="active.steps" />
			</div>

			<details v-if="active.output" class="border-t border-[var(--rule)]">
				<summary class="cursor-pointer px-4 py-2 text-[12px] text-[var(--ink-faint)] hover:text-[var(--ink)]">
					Full output
				</summary>
				<pre
					ref="logEl"
					class="u-mono u-scroll max-h-[340px] overflow-auto whitespace-pre-wrap break-words px-4 pb-3 text-[12px] leading-relaxed"
				>{{ active.output }}</pre>
			</details>
			<p v-else-if="!active.steps?.length" class="px-4 py-3 text-[12px] text-[var(--ink-faint)]">
				waiting for output…
			</p>

			<p v-if="active.error_summary" class="border-t border-[var(--rule)] px-4 py-2.5 text-[12.5px] leading-relaxed">
				{{ active.error_summary }}
			</p>
		</section>

		<DataTable
			:columns="COLUMNS" :rows="rows" :loading="listLoading" :total="total" :start="0"
			:page-length="20"
			empty-title="No installs yet"
			empty-hint="Requests you run appear here with their full command output."
		>
			<template #cell-status="{ row }">
				<button class="flex items-center gap-1.5" @click="open(row.name)">
					<OutcomeMark
						:outcome="['Success', 'Completed With Warnings'].includes(row.status) ? 'Success' : row.status === 'Failed' ? 'Failure' : 'Info'"
						:label="row.status"
					/>
				</button>
			</template>
			<template #cell-app_name="{ row }">
				<span class="u-mono">{{ row.app_name }}</span>
				<span v-if="row.branch" class="ml-1.5 text-[11px] text-[var(--ink-faint)]">{{ row.branch }}</span>
			</template>
		</DataTable>
	</AppShell>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { Button, Spinner, toast } from "frappe-ui";
import { useRoute } from "vue-router";

import AppShell from "../components/AppShell.vue";
import DataTable from "../components/DataTable.vue";
import JobSteps from "../components/JobSteps.vue";
import InstallDialog from "../components/InstallDialog.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import {
	benchesResource,
	installRequestResource, installRequestsResource, settingsResource,
} from "../api";

const deskSettings = "/app/server-settings";
const COLUMNS = [
	{ key: "creation", label: "Requested", type: "datetime", width: "168px" },
	{ key: "status", label: "Status", width: "130px" },
	{ key: "bench", label: "Bench", width: "140px" },
	{ key: "app_name", label: "App", width: "180px" },
	{ key: "install_on_site", label: "Site", muted: true, width: "150px" },
	{ key: "error_summary", label: "Detail", muted: true },
];

const route = useRoute();
const benches = benchesResource();
const settings = settingsResource();
const list = installRequestsResource();
const detail = installRequestResource();

const showForm = ref(false);
const showInstall = ref(false);
const chosenBench = ref("");
const installMode = ref("Clone");
const active = ref(null);
const logEl = ref(null);
let poller = null;

const benchOptions = computed(() => (benches.data || []).filter((b) => b.is_active));
const allowed = computed(() => Boolean(settings.data?.allow_app_install));

function sitesFor(name) {
	return benchOptions.value.find((b) => b.name === name)?.sites.map((s) => s.site_name) || [];
}

function openPull() {
	installMode.value = "Pull";
	showInstall.value = true;
}
const rows = computed(() => list.data?.rows || []);
const total = computed(() => list.data?.total || 0);
const listLoading = computed(() => list.loading && !list.data);
const subtitle = computed(() => (listLoading.value ? "loading…" : `${total.value} request${total.value === 1 ? "" : "s"}`));
function onStarted(name) {
	showForm.value = false;
	showInstall.value = false;
	open(name);
	list.fetch();
}

async function open(name) {
	const data = await detail.submit({ name });
	active.value = data;
	await scrollLog();
	if (!data.is_terminal) startPolling(name);
}

/**
 * Poll while a job is running.
 *
 * Realtime events are published by the worker too, but polling is what makes
 * the log correct after a page reload — a socket only ever carries what
 * happened while you were listening.
 */
function startPolling(name) {
	stopPolling();
	poller = setInterval(async () => {
		try {
			const data = await detail.submit({ name });
			active.value = data;
			await scrollLog();
			if (data.is_terminal) {
				stopPolling();
				list.fetch();
				benches.fetch();
				(['Success', 'Completed With Warnings'].includes(data.status) ? toast.success : toast.error)(
					`${data.name} ${data.status.toLowerCase()}`,
				);
			}
		} catch {
			stopPolling();
		}
	}, 1500);
}

function stopPolling() {
	if (poller) clearInterval(poller);
	poller = null;
}

async function scrollLog() {
	await nextTick();
	if (logEl.value) logEl.value.scrollTop = logEl.value.scrollHeight;
}

watch(showForm, (open) => {
	// Reopening should not carry the last choice of operation.
	if (open) installMode.value = "Clone";
});

onMounted(async () => {
	settings.fetch();
	list.fetch();
	await benches.fetch();
	chosenBench.value = route.query.bench || benchOptions.value[0]?.name || "";
	if (route.query.bench) showForm.value = true;
});

onUnmounted(stopPolling);
</script>
