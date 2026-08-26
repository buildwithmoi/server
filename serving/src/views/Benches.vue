<template>
	<AppShell title="Benches" :subtitle="subtitle">
		<template #actions>
			<!--
				Rescan moves into the menu rather than disappearing. It is still
				the right thing after changing something on disk by hand, but it
				is a maintenance action — and it was occupying the one prominent
				button on a page whose obvious missing verb was "make one".
			-->
			<ActionMenu label="Actions" :options="actions" />
			<Button variant="solid" @click="showProvision = true">
				<template #prefix><Icon name="layers" :size="14" /></template>
				Build a bench
			</Button>
		</template>

		<ProvisionDialog v-model="showProvision" @started="onProvisionStarted" />
		<MigrateDialog v-model="showMigrate" @started="onMigrationStarted" />

		<!-- Git access is a one-line summary here and the full report lives on a
		     bench, because this page is now a list you scan rather than read. -->
		<div v-if="auth.loading && !auth.data" class="u-card mb-3 flex items-center gap-3 px-4 py-2.5">
			<Icon name="key" :size="15" class="shrink-0 text-[var(--ink-ghost)]" />
			<Skeleton height="0.9rem" width="9rem" />
			<Skeleton height="0.9rem" width="16rem" />
		</div>

		<button
			v-else-if="auth.data"
			class="u-card mb-3 flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-[var(--paper-sunk)]"
			@click="showAuth = !showAuth"
		>
			<Icon name="key" :size="15" class="shrink-0" />
			<span class="text-[13px] font-medium">Git access</span>
			<OutcomeMark
				:outcome="auth.data.ok ? 'Success' : 'Failure'"
				:label="auth.data.ok ? 'ready' : `${auth.data.problems.length} issue${auth.data.problems.length === 1 ? '' : 's'}`"
			/>
			<span class="truncate text-[12px] text-[var(--ink-faint)]">
				{{ auth.data.probes.map((p) => `${p.host} → ${p.authenticated_as || "rejected"}`).join(" · ") }}
			</span>
			<Icon name="chevron" :size="14"
			      class="ml-auto shrink-0 text-[var(--ink-ghost)] transition-transform duration-200"
			      :class="showAuth ? 'rotate-90' : ''" />
		</button>

		<Transition
			enter-active-class="transition-all duration-250 ease-[var(--ease)]"
			enter-from-class="opacity-0 -translate-y-2"
			leave-active-class="transition-all duration-150"
			leave-to-class="opacity-0 -translate-y-2"
		>
			<div v-if="showAuth && auth.data" class="u-card mb-3 divide-y divide-[var(--rule)]">
				<div class="flex flex-wrap gap-x-8 gap-y-2 px-4 py-3">
					<div v-for="key in auth.data.keys" :key="key.name" class="text-[13px]">
						<p class="u-mono">{{ key.name }}</p>
						<p class="mt-0.5 text-[11.5px] text-[var(--ink-faint)]">
							{{ key.passphrase_free ? "usable unattended" : "has a passphrase — unusable in a job" }}
							· {{ key.comment || "no comment" }}
						</p>
					</div>
				</div>
				<div v-if="auth.data.problems.length" class="px-4 py-3">
					<ul class="flex flex-col gap-1.5">
						<li v-for="(problem, i) in auth.data.problems" :key="i"
						    class="flex items-start gap-2 text-[12.5px] leading-relaxed">
							<Icon name="alert" :size="14" class="mt-[2px] shrink-0" />
							<span>{{ problem }}</span>
						</li>
					</ul>
					<details class="mt-3">
						<summary class="cursor-pointer text-[12px] text-[var(--ink-faint)] hover:text-[var(--ink)]">
							Show the ~/.ssh/config block to add
						</summary>
						<pre class="u-mono u-scroll mt-2 overflow-x-auto rounded-md border border-[var(--rule)] bg-[var(--paper-sunk)] p-3 text-[12px] leading-relaxed">{{ auth.data.suggested_ssh_config }}</pre>
						<p class="mt-1.5 text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
							Add this yourself and <code class="u-mono">chmod 600 ~/.ssh/config</code>. This app
							never writes to your SSH configuration.
						</p>
					</details>
				</div>
			</div>
		</Transition>

		<!--
			A move that stopped halfway, surfaced where somebody would look for
			it. The detail page existed and nothing linked to it, so a paused
			migration was invisible — and the only apparent way forward was to
			start the whole thing again and re-clone apps already there.
		-->
		<RouterLink
			v-if="unfinishedMove"
			:to="{ name: 'Migration', params: { name: unfinishedMove.name } }"
			class="mb-4 flex items-start gap-3 rounded-lg border border-[var(--ink)] bg-[var(--paper-sunk)] px-4 py-3"
		>
			<Icon name="alert" :size="16" class="mt-0.5 shrink-0" />
			<div class="min-w-0 flex-1">
				<p class="text-[13px] font-medium">
					A bench move is unfinished
				</p>
				<p class="mt-0.5 text-[12.5px] leading-relaxed text-[var(--ink-soft)]">
					<span class="u-mono">{{ unfinishedMove.source_bench }}</span> →
					<span class="u-mono">{{ unfinishedMove.target_bench }}</span>,
					{{ unfinishedMove.done }} of {{ unfinishedMove.total }} steps done<template
						v-if="unfinishedMove.failed"
					>, {{ unfinishedMove.failed }} to retry</template>. Open it to continue.
				</p>
			</div>
		</RouterLink>

		<DataTable
			:columns="COLUMNS"
			:rows="rows"
			:loading="loading"
			:total="rows.length"
			:page-length="100"
			clickable
			:empty-title="emptyTitle"
			:empty-hint="emptyHint"
			@row-click="open"
		>
			<!-- Naming the directory is the whole point. "No benches found" and
			     "I looked in the wrong place" read identically, and the second
			     one is a one-field fix nobody can make without being told where
			     the app actually searched. -->
			<template #empty-extra>
				<!-- The case that matters most: the directory is right, the
				     benches are there, and nothing has read them yet. That is
				     one button, not a diagnosis — so it goes first and the
				     listing below becomes supporting detail. -->
				<div v-if="unscanned" class="mt-4 flex flex-col items-center gap-2">
					<p class="max-w-sm text-[13px] leading-relaxed text-[var(--ink-faint)]">
						{{ report.benches }} {{ report.benches === 1 ? "bench is" : "benches are" }} on disk
						under <span class="u-mono">{{ report.root }}</span>, but none has been read yet.
						This also happens on its own every hour.
					</p>
					<Button variant="solid" :loading="rescanning" @click="rescan">
						<template #prefix><Icon name="refresh" :size="13" /></template>
						Scan them now
					</Button>
				</div>

				<div v-if="report" class="mx-auto mt-4 max-w-xl text-left">
					<dl class="rounded-lg border border-[var(--rule)] bg-[var(--paper-sunk)] p-3 text-[12.5px]">
						<div class="flex gap-2">
							<dt class="w-28 shrink-0 text-[var(--ink-faint)]">Searched</dt>
							<dd class="u-mono break-all">{{ report.root }}</dd>
						</div>
						<div class="mt-1.5 flex gap-2">
							<dt class="w-28 shrink-0 text-[var(--ink-faint)]">Set in</dt>
							<dd>{{ report.configured ? "Settings → Bench Root" : "unset, so this bench's parent" }}</dd>
						</div>
						<div v-if="report.configured && report.configured !== report.default_root" class="mt-1.5 flex gap-2">
							<dt class="w-28 shrink-0 text-[var(--ink-faint)]">This bench</dt>
							<dd class="u-mono break-all">{{ report.default_root }}</dd>
						</div>
					</dl>

					<template v-if="report.candidates.length">
						<p class="mt-3 text-[12.5px] text-[var(--ink-faint)]">
							{{ unscanned ? "What is there:" : "Directories that came close:" }}
						</p>
						<ul class="mt-1.5 space-y-1">
							<li v-for="c in report.candidates" :key="c.path" class="text-[12.5px]">
								<span class="u-mono">{{ c.name }}</span>
								<span class="text-[var(--ink-faint)]"> — {{ c.reason }}</span>
							</li>
						</ul>
					</template>

					<p v-if="!report.exists" class="mt-3 text-[12.5px] u-danger">
						That directory does not exist on this machine. Clear Bench Root in Settings to
						use <span class="u-mono">{{ report.default_root }}</span> instead.
					</p>
					<p v-else-if="!report.readable" class="mt-3 text-[12.5px] u-danger">
						That directory could not be read by the user this app runs as.
					</p>
				</div>
			</template>
			<template #cell-name="{ row }">
				<span class="font-medium">{{ row.name }}</span>
				<span v-if="!row.is_active" class="ml-2 text-[11px] text-[var(--ink-faint)]">missing on disk</span>
			</template>
			<template #cell-ports="{ row }">
				<span class="u-num u-mono">{{ row.webserver_port || "—" }}</span>
				<span class="u-num u-mono ml-2 text-[var(--ink-faint)]">{{ row.socketio_port || "—" }}</span>
			</template>
			<template #cell-apps="{ row }">
				<span class="u-num">{{ row.apps.length }}</span>
			</template>
			<template #cell-sites="{ row }">
				<span class="u-mono">{{ row.default_site || "—" }}</span>
				<span v-if="row.sites.length > 1" class="ml-1.5 text-[11px] text-[var(--ink-faint)]">
					+{{ row.sites.length - 1 }}
				</span>
			</template>
			<template #cell-dirty="{ row }">
				<span v-if="dirtyCount(row)" class="inline-flex items-center gap-1.5 text-[12.5px]">
					<span class="h-1.5 w-1.5 rounded-full bg-[var(--ink)]" />
					{{ dirtyCount(row) }}
				</span>
				<span v-else class="text-[var(--ink-ghost)]">—</span>
			</template>
		</DataTable>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { Button, toast } from "frappe-ui";
import { useRouter } from "vue-router";

import AppShell from "../components/AppShell.vue";
import DataTable from "../components/DataTable.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import Skeleton from "../components/Skeleton.vue";
import ActionMenu from "../components/ActionMenu.vue";
import MigrateDialog from "../components/MigrateDialog.vue";
import ProvisionDialog from "../components/ProvisionDialog.vue";
import { benchMigrationsResource, benchRootReportResource, benchesResource, gitAuthResource, rescanBenchesResource } from "../api";

const COLUMNS = [
	{ key: "name", label: "Bench", width: "170px" },
	{ key: "bench_path", label: "Path", mono: true, muted: true },
	{ key: "ports", label: "Web / Socket", width: "130px" },
	{ key: "frappe_branch", label: "Frappe", width: "110px" },
	{ key: "python_version", label: "Python", width: "90px", muted: true },
	{ key: "apps", label: "Apps", width: "70px" },
	{ key: "sites", label: "Default site", width: "180px" },
	{ key: "dirty", label: "Dirty", width: "80px" },
];

const router = useRouter();
const resource = benchesResource();
const auth = gitAuthResource();
const rootReport = benchRootReportResource();
const moves = benchMigrationsResource();
const rescanning = ref(false);
const showAuth = ref(false);

const rows = computed(() => resource.data || []);
const report = computed(() => rootReport.data || null);

/** The most recent move still waiting on somebody, if there is one. */
const unfinishedMove = computed(() => {
	const rows = moves.data?.rows || [];
	return (
		rows.find(
			(row) =>
				["Running", "Paused", "Cancelled", "Failed"].includes(row.status) &&
				row.done < row.total,
		) || null
	);
});

/** Benches exist on disk; the table simply has not been filled from them. */
const unscanned = computed(() => Boolean(report.value?.benches));

const emptyTitle = computed(() => {
	if (unscanned.value) return "Not scanned yet";
	if (report.value) return `No benches under ${report.value.root}`;
	return "No benches found";
});

const emptyHint = computed(() => {
	if (unscanned.value) return "";
	if (report.value && !report.value.exists) return "That directory does not exist on this machine.";
	if (report.value && !report.value.readable) return "That directory could not be read.";
	return "A directory counts as a bench only if it has apps, sites, config, logs and config/pids.";
});
const loading = computed(() => resource.loading && !resource.data);
const subtitle = computed(() =>
	loading.value ? "scanning…" : `${rows.value.length} found on this machine`,
);

const dirtyCount = (bench) => bench.apps.filter((a) => a.is_dirty).length;
const open = (bench) => router.push({ name: "BenchDetail", params: { name: bench.name } });

const showProvision = ref(false);
const showMigrate = ref(false);

const actions = computed(() => [
	{
		label: "Move a bench here…",
		icon: "server",
		description: "Bring every site on a bench from another server, building it here first.",
		danger: true,
		onClick: () => (showMigrate.value = true),
	},
	{
		label: "Rescan benches",
		icon: "refresh",
		description: "Re-read every bench from disk — after changing one by hand.",
		onClick: rescan,
	},
]);

function onMigrationStarted(name) {
	// Each step is an ordinary job, so the dock already shows them one by one.
	// The migration row is what says how far through the whole thing it is.
	router.push({ name: "Migration", params: { name } });
}

function onProvisionStarted() {
	// The dock owns the job from here. A rescan once it is likely to have
	// finished is cosmetic; the job's own last step does the real one.
	setTimeout(() => resource.fetch(), 4000);
}

async function rescan() {
	rescanning.value = true;
	try {
		const result = await rescanBenchesResource().submit({});
		toast.success(`Found ${result.found} bench${result.found === 1 ? "" : "es"} under ${result.root}`);
		await resource.fetch();
		// The diagnosis is now stale, and leaving it would show a panel saying
		// benches are waiting to be read directly beneath the scan that read them.
		if (!rows.value.length) rootReport.fetch();
	} catch (error) {
		toast.error(error.messages?.[0] || "Rescan failed");
	} finally {
		rescanning.value = false;
	}
}

onMounted(async () => {
	await resource.fetch();
	auth.fetch();
	moves.fetch();
	// Only when there is nothing to show. On a working machine this is a
	// directory listing nobody needs, and the empty state is the only place
	// its answer is used.
	if (!rows.value.length) rootReport.fetch();
});
</script>
