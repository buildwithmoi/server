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

		<DataTable
			:columns="COLUMNS"
			:rows="rows"
			:loading="loading"
			:total="rows.length"
			:page-length="100"
			clickable
			empty-title="No benches found"
			empty-hint="Nothing under the configured Bench Root looks like a bench. A directory counts only if it has apps, sites, config, logs and config/pids."
			@row-click="open"
		>
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
import ProvisionDialog from "../components/ProvisionDialog.vue";
import { benchesResource, gitAuthResource, rescanBenchesResource } from "../api";

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
const rescanning = ref(false);
const showAuth = ref(false);

const rows = computed(() => resource.data || []);
const loading = computed(() => resource.loading && !resource.data);
const subtitle = computed(() =>
	loading.value ? "scanning…" : `${rows.value.length} found on this machine`,
);

const dirtyCount = (bench) => bench.apps.filter((a) => a.is_dirty).length;
const open = (bench) => router.push({ name: "BenchDetail", params: { name: bench.name } });

const showProvision = ref(false);

const actions = computed(() => [
	{
		label: "Rescan benches",
		icon: "refresh",
		description: "Re-read every bench from disk — after changing one by hand.",
		onClick: rescan,
	},
]);

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
		resource.fetch();
	} catch (error) {
		toast.error(error.messages?.[0] || "Rescan failed");
	} finally {
		rescanning.value = false;
	}
}

onMounted(() => {
	resource.fetch();
	auth.fetch();
});
</script>
