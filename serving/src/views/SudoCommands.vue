<template>
	<AppShell title="Sudo Commands" :subtitle="subtitle">
		<template #actions>
			<div class="relative">
				<Icon name="search" :size="14"
				      class="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--ink-ghost)]" />
				<input
					v-model="search"
					type="search"
					placeholder="Search commands…"
					class="w-44 rounded-md border border-[var(--rule)] bg-[var(--paper)] py-1.5 pl-8 pr-2.5 text-[13px] outline-none transition-colors focus:border-[var(--ink)] sm:w-56"
					@input="debouncedReload"
				/>
			</div>
			<select v-model="status" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" @change="reload(0)">
				<option value="">All</option>
				<option>Executed</option>
				<option>Denied</option>
				<option>Auth Failure</option>
			</select>
		</template>

		<p class="mb-3 max-w-2xl text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			Without auditd installed, sudo is the richest record of what someone actually did once
			they were in — it captures the full command line, the working directory and the account
			it ran as.
		</p>

		<DataTable
			:columns="COLUMNS" :rows="rows" :loading="loading" :total="total" :start="start"
			:page-length="PAGE"
			empty-title="No sudo activity"
			empty-hint="Nothing has been run through sudo in the recorded window."
			@page="reload"
		>
			<template #cell-status="{ row }">
				<OutcomeMark
					:outcome="row.status === 'Executed' ? 'Success' : 'Failure'"
					:label="row.status"
				/>
			</template>
			<template #cell-command="{ row }">
				<span class="u-mono break-all">{{ row.command || row.failure_reason || "—" }}</span>
			</template>
		</DataTable>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import DataTable from "../components/DataTable.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import { sudoCommandsResource } from "../api";

const PAGE = 50;
const COLUMNS = [
	{ key: "event_time", label: "When", type: "datetime", width: "168px" },
	{ key: "status", label: "Status", width: "140px" },
	{ key: "actor", label: "Actor", mono: true, width: "120px" },
	{ key: "target_user", label: "Ran as", mono: true, width: "110px" },
	{ key: "pwd", label: "Directory", mono: true, muted: true, width: "190px" },
	{ key: "command", label: "Command" },
];

const resource = sudoCommandsResource();
const start = ref(0);
const status = ref("");
const search = ref("");

const rows = computed(() => resource.data?.rows || []);
const total = computed(() => resource.data?.total || 0);
const loading = computed(() => resource.loading);
const subtitle = computed(() => (loading.value ? "loading…" : `${total.value.toLocaleString()} recorded`));

function reload(nextStart = 0) {
	start.value = nextStart;
	resource
		.submit({ start: nextStart, page_length: PAGE, status: status.value || null, search: search.value || null })
		.catch((error) => toast.error(error.messages?.[0] || "Could not load commands"));
}

let timer;
function debouncedReload() {
	clearTimeout(timer);
	timer = setTimeout(() => reload(0), 280);
}

onMounted(() => reload(0));
</script>
