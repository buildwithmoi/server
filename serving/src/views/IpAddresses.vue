<template>
	<AppShell title="Addresses" :subtitle="subtitle">
		<template #actions>
			<select v-model="status" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" @change="reload(0)">
				<option value="">All</option>
				<option>Resolved</option>
				<option>Pending</option>
				<option>Private</option>
				<option>Failed</option>
			</select>
			<Button :loading="resolving" @click="resolveNow">
				<template #prefix><Icon name="globe" :size="14" /></template>
				Resolve now
			</Button>
		</template>

		<p class="mb-3 max-w-2xl text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			Each address is looked up once and cached here. Private and loopback ranges are marked
			<em>Private</em> and are never sent to the geolocation provider.
		</p>

		<DataTable
			:columns="COLUMNS" :rows="rows" :loading="loading" :total="total" :start="start"
			:page-length="PAGE"
			empty-title="No addresses seen"
			empty-hint="Addresses appear here the first time they show up in an SSH event."
			@page="reload"
		>
			<template #cell-status="{ row }">
				<OutcomeMark
					:outcome="statusOutcome(row.status)"
					:label="row.status"
				/>
			</template>
			<template #cell-country="{ row }">
				<span v-if="row.country">{{ row.country }}</span>
				<span v-else class="text-[var(--ink-faint)]">—</span>
				<span v-if="row.city" class="ml-1.5 text-[11px] text-[var(--ink-faint)]">{{ row.city }}</span>
			</template>
		</DataTable>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { Button, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import DataTable from "../components/DataTable.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import { ipAddressesResource, resolveGeoResource } from "../api";

const PAGE = 50;
const COLUMNS = [
	{ key: "ip_address", label: "Address", mono: true, width: "215px" },
	{ key: "status", label: "Status", width: "130px" },
	{ key: "country", label: "Location", width: "220px" },
	{ key: "isp", label: "Network", muted: true },
	{ key: "last_seen", label: "Last seen", type: "datetime", width: "168px" },
];

const resource = ipAddressesResource();
const start = ref(0);
const status = ref("");
const resolving = ref(false);

const rows = computed(() => resource.data?.rows || []);
const total = computed(() => resource.data?.total || 0);
const loading = computed(() => resource.loading);
const subtitle = computed(() => (loading.value ? "loading…" : `${total.value.toLocaleString()} cached`));

// Private is neither good nor bad — it is simply not lookup-able, so it gets
// the neutral mark rather than being dressed up as a failure.
const statusOutcome = (value) =>
	({ Resolved: "Success", Failed: "Failure", Pending: "Info", Private: "Info" })[value] || "Info";

function reload(nextStart = 0) {
	start.value = nextStart;
	resource
		.submit({ start: nextStart, page_length: PAGE, status: status.value || null })
		.catch((error) => toast.error(error.messages?.[0] || "Could not load addresses"));
}

async function resolveNow() {
	resolving.value = true;
	try {
		const result = await resolveGeoResource().submit({ backfill_all: true });
		if (result.error) {
			toast.error(result.error);
		} else {
			toast.success(
				result.resolved
					? `Resolved ${result.resolved}, updated ${result.events_backfilled || 0} events`
					: result.reason || "Nothing pending",
			);
		}
		reload(start.value);
	} catch (error) {
		toast.error(error.messages?.[0] || "Lookup failed");
	} finally {
		resolving.value = false;
	}
}

onMounted(() => reload(0));
</script>
