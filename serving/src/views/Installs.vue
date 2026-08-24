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

		<Transition
			enter-active-class="transition-all duration-250 ease-[var(--ease)]"
			enter-from-class="opacity-0 -translate-y-2"
			leave-active-class="transition-all duration-150 ease-[var(--ease)]"
			leave-to-class="opacity-0 -translate-y-2"
		>
			<form v-if="showForm" class="u-card mb-3 p-4" @submit.prevent="submit">
				<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
					<label class="flex flex-col gap-1.5">
						<span class="u-label">Bench</span>
						<select v-model="form.bench" required class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]">
							<option v-for="b in benchOptions" :key="b.name" :value="b.name">{{ b.name }}</option>
						</select>
					</label>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">Organisation</span>
						<select v-model="form.github_org" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]">
							<option>Carbonite-Solutions-Ltd</option>
							<option>buildwithmoi</option>
						</select>
					</label>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">Repository</span>
						<input v-model.trim="form.repo" required placeholder="gh_erp"
						       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
					</label>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">Branch</span>
						<input v-model.trim="form.branch" placeholder="leave blank for default"
						       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
					</label>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">Install on site</span>
						<select v-model="form.install_on_site" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]">
							<option value="">clone only, do not install</option>
							<option v-for="s in siteOptions" :key="s" :value="s">{{ s }}</option>
						</select>
					</label>

					<div class="flex flex-col justify-end gap-2 pb-1">
						<label class="flex items-center gap-2 text-[12.5px]">
							<input v-model="form.skip_assets" type="checkbox" class="accent-[var(--ink)]" />
							Skip asset build
						</label>
						<label class="flex items-center gap-2 text-[12.5px]">
							<input v-model="form.overwrite_existing" type="checkbox" class="accent-[var(--ink)]" />
							Overwrite if present
						</label>
					</div>
				</div>

				<p class="mt-3 text-[12px] leading-relaxed text-[var(--ink-faint)]">
					Leave <em>Skip asset build</em> on — building assets is the largest memory consumer in a
					bench operation and the step most likely to take a small server down. Run
					<code class="u-mono">bench build --app &lt;name&gt;</code> by hand when the box is idle.
				</p>

				<div class="mt-3 flex flex-wrap items-center gap-2">
					<Button :loading="checking" @click="checkAccess">
						<template #prefix><Icon name="key" :size="14" /></template>
						Check access
					</Button>
					<Button variant="solid" type="submit" :loading="submitting" :disabled="!canSubmit">
						<template #prefix><Icon name="play" :size="14" /></template>
						Clone &amp; install
					</Button>
					<p v-if="probe" class="flex items-center gap-1.5 text-[12.5px]">
						<OutcomeMark :outcome="probe.ok ? 'Success' : 'Failure'" :label="probe.text" />
					</p>
				</div>
			</form>
		</Transition>

		<!-- live log for whatever is running or was last opened -->
		<section v-if="active" class="u-card mb-3 overflow-hidden">
			<header class="flex items-center justify-between gap-3 border-b border-[var(--rule)] px-4 py-3">
				<div class="flex min-w-0 items-center gap-2.5">
					<Spinner v-if="!active.is_terminal" class="h-3.5 w-3.5 shrink-0" />
					<OutcomeMark v-else :outcome="active.status === 'Success' ? 'Success' : 'Failure'" :label="active.status" />
					<span class="u-mono truncate text-[13px]">{{ active.name }} · {{ active.app_name }}</span>
				</div>
				<button class="text-[12px] text-[var(--ink-faint)] hover:text-[var(--ink)]" @click="active = null">
					Close
				</button>
			</header>

			<p v-if="active.command" class="u-mono border-b border-[var(--rule)] bg-[var(--paper-sunk)] px-4 py-2 text-[11.5px] text-[var(--ink-soft)]">
				$ {{ active.command }}
			</p>

			<pre
				ref="logEl"
				class="u-mono u-scroll max-h-[340px] overflow-auto whitespace-pre-wrap break-words px-4 py-3 text-[12px] leading-relaxed"
			>{{ active.output || "waiting for output…" }}</pre>

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
						:outcome="row.status === 'Success' ? 'Success' : row.status === 'Failed' ? 'Failure' : 'Info'"
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
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import {
	benchesResource, checkRepoResource, createInstallResource,
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
const submitting = ref(false);
const checking = ref(false);
const probe = ref(null);
const active = ref(null);
const logEl = ref(null);
let poller = null;

const form = ref({
	bench: "",
	github_org: "Carbonite-Solutions-Ltd",
	repo: "",
	branch: "",
	install_on_site: "",
	skip_assets: true,
	overwrite_existing: false,
});

const benchOptions = computed(() => (benches.data || []).filter((b) => b.is_active));
const siteOptions = computed(
	() => benchOptions.value.find((b) => b.name === form.value.bench)?.sites.map((s) => s.site_name) || [],
);
const rows = computed(() => list.data?.rows || []);
const total = computed(() => list.data?.total || 0);
const listLoading = computed(() => list.loading && !list.data);
const subtitle = computed(() => (listLoading.value ? "loading…" : `${total.value} request${total.value === 1 ? "" : "s"}`));
const canSubmit = computed(
	() => Boolean(form.value.bench && form.value.repo) && Boolean(settings.data?.allow_app_install),
);

async function checkAccess() {
	if (!form.value.repo) return;
	checking.value = true;
	probe.value = null;
	try {
		const url = `git@github.com:${form.value.github_org}/${form.value.repo.replace(/\.git$/, "")}.git`;
		const result = await checkRepoResource().submit({ git_url: url, branch: form.value.branch || null });
		probe.value = result.reachable && result.branch_exists
			? { ok: true, text: form.value.branch ? `${form.value.branch} found` : `${result.branches?.length || 0} branches` }
			: { ok: false, text: result.error || "not reachable" };
	} catch (error) {
		probe.value = { ok: false, text: error.messages?.[0] || "check failed" };
	} finally {
		checking.value = false;
	}
}

async function submit() {
	submitting.value = true;
	try {
		const result = await createInstallResource().submit({ ...form.value, run: true });
		toast.success(`${result.name} queued`);
		showForm.value = false;
		open(result.name);
		list.fetch();
	} catch (error) {
		toast.error(error.messages?.[0] || "Could not start the install");
	} finally {
		submitting.value = false;
	}
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
				(data.status === "Success" ? toast.success : toast.error)(
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

watch(() => form.value.repo, () => (probe.value = null));
watch(() => form.value.bench, () => (form.value.install_on_site = ""));

onMounted(async () => {
	settings.fetch();
	list.fetch();
	await benches.fetch();
	form.value.bench = route.query.bench || benchOptions.value[0]?.name || "";
	if (route.query.bench) showForm.value = true;
});

onUnmounted(stopPolling);
</script>
