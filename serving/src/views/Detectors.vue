<template>
	<AppShell title="Detectors" :subtitle="subtitle">
		<template #actions>
			<Button variant="subtle" :loading="scanning" @click="scanNow">Run all scans</Button>
		</template>

		<!--
			THE POINT OF THIS PAGE. Findings tell you what was seen; this tells
			you whether anything is looking. A detector that has quietly stopped
			produces the same empty screen as a clean host, and on the intrusion
			this app was written after, the empty screen lasted eight months.
		-->
		<section class="mb-6">
			<h2 class="u-display mb-2 text-[13.5px]">Is anything watching?</h2>
			<div v-if="loading && !detectors.length" class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
				<Skeleton v-for="n in 6" :key="n" class="h-[76px]" />
			</div>
			<div v-else class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
				<div
					v-for="d in detectors"
					:key="d.source"
					class="rounded-lg border bg-[var(--paper)] p-3"
					:class="health(d).late || d.last_status === 'Error'
						? 'border-[var(--danger-border)]'
						: 'border-[var(--rule)]'"
				>
					<div class="flex items-baseline justify-between gap-2">
						<span class="u-mono text-[13px]">{{ d.source }}</span>
						<span class="text-[11.5px]" :class="health(d).class">{{ health(d).label }}</span>
					</div>
					<p class="mt-1.5 text-[11.5px] text-[var(--ink-faint)]">
						ran {{ ago(d.last_run) }} · every {{ Math.round(d.expected_every / 60) }} min
					</p>
					<p class="mt-0.5 text-[11.5px] text-[var(--ink-faint)]">
						completed {{ d.sequence }}×
					</p>
				</div>
			</div>
			<p v-if="!loading && !detectors.length" class="text-[13px] text-[var(--ink-faint)]">
				No detector has reported yet. They record a heartbeat the first time they run.
			</p>
		</section>

		<!-- Off-box state. Everything above runs on the machine it watches, so
		     these two lines are what say whether any of it survives that
		     machine being the problem. -->
		<section class="mb-6">
			<h2 class="u-display mb-2 text-[13.5px]">If this host were the problem</h2>
			<div class="grid gap-2 sm:grid-cols-2">
				<div class="rounded-lg border border-[var(--rule)] bg-[var(--paper)] p-3">
					<p class="text-[13px]">
						{{ overview.forwarding_configured ? "Findings are copied off this host" : "Findings exist only here" }}
					</p>
					<p class="mt-1 text-[11.5px] text-[var(--ink-faint)]">
						<template v-if="overview.forwarding_configured">
							{{ overview.undelivered || 0 }} waiting to be delivered.
						</template>
						<template v-else>
							Nothing is forwarding them. Anyone who can edit this database can remove
							a record of themselves. Set a collector in Settings.
						</template>
					</p>
				</div>
				<div class="rounded-lg border border-[var(--rule)] bg-[var(--paper)] p-3">
					<p class="text-[13px]">Last finding recorded {{ ago(overview.last_scan) }}</p>
					<p class="mt-1 text-[11.5px] text-[var(--ink-faint)]">
						A watcher elsewhere can poll this host's heartbeat and alert when it stops
						climbing — a process that has been stopped cannot notice it has been stopped.
					</p>
				</div>
			</div>
		</section>

		<!-- The inventory: what is being compared against, and how much of it
		     nobody has looked at yet. -->
		<section>
			<div class="mb-2 flex flex-wrap items-center justify-between gap-2">
				<h2 class="u-display text-[13.5px]">What is being watched</h2>
				<Button
					v-if="unreviewedTotal"
					variant="subtle"
					:loading="accepting"
					@click="acceptBaseline"
				>
					Mark all {{ unreviewedTotal }} as reviewed
				</Button>
			</div>

			<p v-if="unreviewedTotal" class="mb-3 rounded-md border border-[var(--warn-border)] bg-[var(--warn-bg)] px-3 py-2 text-[12.5px] leading-relaxed">
				{{ unreviewedTotal }} recorded items have never been reviewed. Until they are, these
				detectors can only report what <em>changes</em> from here — they cannot tell you
				whether what is already on the host belongs. A server rebuilt from a snapshot of a
				compromised machine would record that machine's leftovers as normal.
			</p>

			<div class="mb-3 flex flex-wrap gap-1.5">
				<button
					v-for="k in KINDS"
					:key="k.key"
					type="button"
					class="rounded-md border px-2.5 py-1.5 text-[12.5px] transition-colors"
					:class="kind === k.key
						? 'border-[var(--ink)] bg-[var(--paper-sunk)]'
						: 'border-[var(--rule)] bg-[var(--paper)] hover:border-[var(--rule-strong)]'"
					@click="selectKind(k.key)"
				>
					{{ k.label }}
					<span class="ml-1 text-[var(--ink-faint)]">{{ counts[k.key] ?? "" }}</span>
				</button>
			</div>

			<DataTable
				:columns="COLUMNS[kind]"
				:rows="inventoryRows"
				:loading="inventory.loading"
				:total="inventoryTotal"
				:start="inventoryStart"
				:page-length="PAGE"
				empty-title="Nothing recorded yet"
				empty-hint="The detector records what it finds the first time it runs."
				@page="loadInventory"
			>
				<template #cell-is_baseline="{ row }">
					<span v-if="row.is_baseline" class="text-[12px] text-[var(--ink-faint)]">reviewed</span>
					<span v-else class="text-[12px] text-[var(--warn)]">not reviewed</span>
				</template>
				<template #cell-package="{ row }">
					<span v-if="row.package" class="u-mono text-[12px]">{{ row.package }}</span>
					<span v-else class="text-[12px] text-[var(--warn)]">no package</span>
				</template>
				<template #cell-listening_publicly="{ row }">
					<span v-if="row.listening_publicly" class="text-[12px] text-[var(--warn)]">public</span>
					<span v-else class="text-[12px] text-[var(--ink-faint)]">local</span>
				</template>
			</DataTable>
		</section>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import DataTable from "../components/DataTable.vue";
import Skeleton from "../components/Skeleton.vue";
import {
	acceptBaselineResource,
	runSecurityScanResource,
	securityInventoryResource,
	securityOverviewResource,
} from "../api";

const PAGE = 50;

const KINDS = [
	{ key: "persistence", label: "Persistence" },
	{ key: "accounts", label: "Accounts" },
	{ key: "keys", label: "SSH keys" },
	{ key: "sockets", label: "Listening ports" },
	{ key: "files", label: "Files" },
];

const COLUMNS = {
	persistence: [
		{ key: "kind", label: "Kind", width: "130px", mono: true },
		{ key: "identifier", label: "Identifier", mono: true },
		{ key: "package", label: "Package", width: "150px" },
		{ key: "is_baseline", label: "Reviewed", width: "110px" },
	],
	accounts: [
		{ key: "username", label: "User", width: "140px", mono: true },
		{ key: "uid", label: "UID", width: "70px" },
		{ key: "shell", label: "Shell", mono: true, muted: true },
		{ key: "password_status", label: "Password", width: "110px" },
		{ key: "is_baseline", label: "Reviewed", width: "110px" },
	],
	keys: [
		{ key: "account", label: "Account", width: "130px", mono: true },
		{ key: "key_type", label: "Type", width: "110px" },
		{ key: "fingerprint", label: "Fingerprint", mono: true },
		{ key: "comment", label: "Comment", muted: true },
		{ key: "is_baseline", label: "Reviewed", width: "110px" },
	],
	sockets: [
		{ key: "port", label: "Port", width: "80px" },
		{ key: "protocol", label: "Proto", width: "80px" },
		{ key: "local_address", label: "Address", mono: true, width: "180px" },
		{ key: "process_name", label: "Process", mono: true, width: "140px" },
		{ key: "listening_publicly", label: "Exposure", width: "100px" },
		{ key: "is_baseline", label: "Reviewed", width: "110px" },
	],
	files: [
		{ key: "kind", label: "Kind", width: "140px", mono: true },
		{ key: "path", label: "Path", mono: true },
		{ key: "package", label: "Package", width: "150px" },
		{ key: "is_baseline", label: "Reviewed", width: "110px" },
	],
};

const overviewResource = securityOverviewResource();
const inventory = securityInventoryResource();
const scanResource = runSecurityScanResource();
const baselineResource = acceptBaselineResource();

const kind = ref("persistence");
const inventoryStart = ref(0);
const scanning = ref(false);
const accepting = ref(false);
const counts = ref({});

const overview = computed(() => overviewResource.data || {});
const detectors = computed(() => overview.value.detectors || []);
const loading = computed(() => overviewResource.loading);
const inventoryRows = computed(() => inventory.data?.rows || []);
const inventoryTotal = computed(() => inventory.data?.total || 0);
const unreviewedTotal = computed(() => overview.value.unreviewed || 0);

const subtitle = computed(() => {
	if (loading.value && !detectors.length) return "loading…";
	const late = detectors.value.filter((d) => health(d).late).length;
	if (late) return `${late} not reporting`;
	return detectors.value.length ? `${detectors.value.length} running` : "none running";
});

/**
 * Late is measured against the detector's own schedule with the same tolerance
 * the backend uses, so the console and the alerting never disagree about
 * whether something has stopped.
 */
const LATE_MULTIPLIER = 2.5;
function health(d) {
	if (d.last_status === "Error") {
		return { label: "erroring", class: "text-[var(--danger)]", late: false };
	}
	if (!d.last_run) return { label: "never run", class: "text-[var(--warn)]", late: true };
	const seconds = (Date.now() - new Date(d.last_run.replace(" ", "T")).getTime()) / 1000;
	if (seconds > (d.expected_every || 900) * LATE_MULTIPLIER) {
		return { label: "not reporting", class: "text-[var(--danger)]", late: true };
	}
	return { label: "ok", class: "text-[var(--ok)]", late: false };
}

function ago(value) {
	if (!value) return "never";
	const date = new Date(value.replace(" ", "T"));
	if (Number.isNaN(date.getTime())) return value;
	const minutes = Math.round((Date.now() - date.getTime()) / 60000);
	if (minutes < 1) return "just now";
	if (minutes < 60) return `${minutes}m ago`;
	if (minutes < 60 * 24) return `${Math.round(minutes / 60)}h ago`;
	return `${Math.round(minutes / 1440)}d ago`;
}

function loadInventory(nextStart = 0) {
	inventoryStart.value = nextStart;
	inventory
		.submit({ kind: kind.value, start: nextStart, page_length: PAGE })
		.then((data) => {
			counts.value = { ...counts.value, [kind.value]: data.total };
		})
		.catch((error) => toast.error(error.messages?.[0] || "Could not load the inventory"));
}

function selectKind(next) {
	kind.value = next;
	loadInventory(0);
}

function refresh() {
	overviewResource.submit().catch(() => {});
}

async function scanNow() {
	scanning.value = true;
	try {
		await scanResource.submit({ record_only: 0 });
		toast.success("Scans finished");
		refresh();
		loadInventory(inventoryStart.value);
	} catch (error) {
		toast.error(error.messages?.[0] || "The scan could not be started");
	} finally {
		scanning.value = false;
	}
}

async function acceptBaseline() {
	accepting.value = true;
	try {
		await baselineResource.submit();
		toast.success("Baseline accepted");
		refresh();
		loadInventory(inventoryStart.value);
	} catch (error) {
		toast.error(error.messages?.[0] || "Could not accept the baseline");
	} finally {
		accepting.value = false;
	}
}

onMounted(() => {
	refresh();
	loadInventory(0);
});
</script>
