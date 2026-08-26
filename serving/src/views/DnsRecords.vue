<template>
	<AppShell title="DNS records" :subtitle="subtitle">
		<template #actions>
			<Button v-if="zone" variant="subtle" :loading="loading" @click="load">
				<template #prefix><Icon name="refresh" :size="13" /></template>
				Refresh
			</Button>
			<Button v-if="zone" variant="solid" @click="startNew">
				<template #prefix><Icon name="globe" :size="13" /></template>
				Add a record
			</Button>
		</template>

		<p class="mb-4 text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			Read straight from the registrar every time, never from a copy kept here — half of
			these records were made in the registrar's own console, and a cached copy of somebody
			else's DNS is wrong the moment they touch it.
		</p>

		<div class="mb-4 grid gap-3 sm:grid-cols-2">
			<label class="flex flex-col gap-1.5">
				<span class="u-label">Provider</span>
				<select
					v-model="provider"
					class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
					@change="onProvider"
				>
					<option value="">Choose a provider</option>
					<option v-for="p in providers" :key="p.name" :value="p.name">
						{{ p.provider_name }} ({{ p.provider }})
					</option>
				</select>
			</label>

			<label class="flex flex-col gap-1.5">
				<span class="u-label">Domain</span>
				<select
					v-model="zone"
					:disabled="!zones.length"
					class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)] disabled:opacity-60"
					@change="load"
				>
					<option value="">{{ zones.length ? "Choose a domain" : "No domains on that credential" }}</option>
					<option v-for="z in zones" :key="z" :value="z">{{ z }}</option>
				</select>
			</label>
		</div>

		<p v-if="error" class="u-note u-note-danger mb-4 text-[12.5px] leading-relaxed">{{ error }}</p>

		<div v-if="loading" class="space-y-2">
			<Skeleton v-for="n in 4" :key="n" class="h-11" />
		</div>

		<EmptyState
			v-else-if="!zone"
			title="Pick a domain"
			icon="globe"
			hint="Its records are fetched live from the provider."
		/>

		<EmptyState
			v-else-if="!records.length"
			title="No records in that zone"
			icon="globe"
			hint="Either it is empty, or the credential cannot read it."
		/>

		<div v-else class="u-card overflow-hidden">
			<div class="u-scroll overflow-x-auto">
				<table class="w-full text-[12.5px]">
					<thead>
						<tr class="border-b border-[var(--rule)] text-left text-[11px] uppercase tracking-wide text-[var(--ink-faint)]">
							<th class="px-3 py-2 font-medium">Name</th>
							<th class="px-3 py-2 font-medium">Type</th>
							<th class="px-3 py-2 font-medium">Points at</th>
							<th class="px-3 py-2 font-medium">TTL</th>
							<th class="px-3 py-2"></th>
						</tr>
					</thead>
					<tbody>
						<tr
							v-for="row in records"
							:key="`${row.type}-${row.name}-${row.content}`"
							class="border-b border-[var(--rule)] last:border-0"
						>
							<td class="u-mono px-3 py-2">{{ fqdn(row.name) }}</td>
							<td class="px-3 py-2 text-[var(--ink-faint)]">{{ row.type }}</td>
							<td class="u-mono px-3 py-2">
								{{ row.content }}
								<!-- The one fact worth not making somebody hold in their head. -->
								<span v-if="row.content === thisHost" class="ml-1.5 text-[11px] u-ok">this server</span>
							</td>
							<td class="u-num px-3 py-2 text-[var(--ink-faint)]">{{ row.ttl }}</td>
							<td class="px-3 py-2 text-right">
								<Button size="sm" variant="ghost" @click="startEdit(row)">Edit</Button>
								<Button size="sm" variant="ghost" @click="startDelete(row)">Remove</Button>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>

		<Dialog v-model="editing" :options="{ title: form.record_id || form.existing ? 'Change a record' : 'Add a record' }">
			<template #body-content>
				<div class="flex flex-col gap-3.5">
					<div class="grid gap-3 sm:grid-cols-2">
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Name</span>
							<input
								v-model.trim="form.label"
								placeholder="app  (or @ for the domain itself)"
								class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
							/>
							<span class="text-[11.5px] text-[var(--ink-faint)]">{{ previewName }}</span>
						</label>
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Type</span>
							<select
								v-model="form.record_type"
								class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
							>
								<option v-for="t in TYPES" :key="t" :value="t">{{ t }}</option>
							</select>
						</label>
					</div>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">Points at</span>
						<div class="flex gap-2">
							<input
								v-model.trim="form.content"
								placeholder="203.0.113.10"
								class="u-mono min-w-0 flex-1 rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
							/>
							<Button v-if="thisHost" variant="subtle" @click="form.content = thisHost">
								Use this server
							</Button>
						</div>
					</label>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">TTL (seconds)</span>
						<input
							v-model.number="form.ttl"
							inputmode="numeric"
							class="u-mono w-32 rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
						/>
					</label>

					<!--
						Typed out, for the same reason pointing a domain here
						asks: this is not reversible on anybody else's schedule.
						A wrong record propagates and is cached by resolvers
						that never asked this app's permission.
					-->
					<div class="u-note u-note-danger flex flex-col gap-2">
						<p class="text-[12.5px] leading-relaxed">
							This writes a public DNS record. Type
							<span class="u-mono font-medium">{{ previewName }}</span> to confirm.
						</p>
						<input
							v-model.trim="form.confirm"
							:placeholder="previewName"
							class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
						/>
					</div>

					<p v-if="formError" class="text-[12.5px] u-danger">{{ formError }}</p>
				</div>
			</template>
			<template #actions>
				<Button variant="ghost" @click="editing = false">Cancel</Button>
				<Button variant="solid" :loading="saving" :disabled="!canSave" @click="save">
					{{ removing ? "Remove it" : "Write the record" }}
				</Button>
			</template>
		</Dialog>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from "vue";
import { Button, Dialog, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import Skeleton from "../components/Skeleton.vue";
import {
	deleteDnsRecordResource,
	dnsRecordsResource,
	domainProvidersResource,
	saveDnsRecordResource,
} from "../api";

const TYPES = ["A", "AAAA", "CNAME", "TXT", "MX"];

const providersRes = domainProvidersResource();
const recordsRes = dnsRecordsResource();
const saveRes = saveDnsRecordResource();
const deleteRes = deleteDnsRecordResource();

const provider = ref("");
const zone = ref("");
const editing = ref(false);
const removing = ref(false);
const saving = ref(false);
const error = ref("");
const formError = ref("");

const form = reactive({
	label: "",
	record_type: "A",
	content: "",
	ttl: 3600,
	record_id: "",
	existing: false,
	confirm: "",
});

const providers = computed(() => providersRes.data?.providers || []);
const zones = computed(() => providers.value.find((p) => p.name === provider.value)?.zones || []);
const records = computed(() => recordsRes.data?.records || []);
const thisHost = computed(() => recordsRes.data?.this_host || "");
const loading = computed(() => recordsRes.loading);

const subtitle = computed(() => {
	if (!zone.value) return "choose a domain";
	return loading.value ? "loading…" : `${records.value.length} in ${zone.value}`;
});

const previewName = computed(() => {
	const label = (form.label || "@").replace(/\.$/, "");
	return label === "@" ? zone.value : `${label}.${zone.value}`;
});

const canSave = computed(() => {
	if (form.confirm !== previewName.value) return false;
	return removing.value || Boolean(form.content);
});

function fqdn(label) {
	return !label || label === "@" ? zone.value : `${label}.${zone.value}`;
}

function onProvider() {
	zone.value = "";
	recordsRes.reset?.();
}

function load() {
	error.value = "";
	if (!provider.value || !zone.value) return;
	recordsRes
		.submit({ name: provider.value, zone: zone.value })
		.then((result) => {
			// The provider answering is not the provider succeeding — every
			// call in this module returns a result rather than raising.
			if (result && result.ok === false) error.value = result.error || "The provider refused.";
		})
		.catch((caught) => (error.value = caught.messages?.[0] || "Could not read that zone"));
}

function reset(row = null) {
	form.label = row?.name || "";
	form.record_type = row?.type || "A";
	form.content = row?.content || "";
	form.ttl = row?.ttl || 3600;
	form.record_id = row?.record_id || "";
	form.existing = Boolean(row);
	form.confirm = "";
	formError.value = "";
}

function startNew() {
	removing.value = false;
	reset();
	editing.value = true;
}

function startEdit(row) {
	removing.value = false;
	reset(row);
	editing.value = true;
}

function startDelete(row) {
	removing.value = true;
	reset(row);
	editing.value = true;
}

async function save() {
	saving.value = true;
	formError.value = "";
	try {
		const call = removing.value ? deleteRes : saveRes;
		const result = await call.submit({
			name: provider.value,
			zone: zone.value,
			label: form.label || "@",
			record_type: form.record_type,
			content: form.content,
			ttl: form.ttl,
			record_id: form.record_id,
			confirm: form.confirm,
		});
		if (result.ok === false) {
			formError.value = result.error || "The provider refused it.";
			return;
		}
		toast.success(removing.value ? `${result.fqdn} removed` : `${result.fqdn} written`);
		editing.value = false;
		load();
	} catch (caught) {
		formError.value = caught.messages?.[0] || "Could not write that record";
	} finally {
		saving.value = false;
	}
}

onMounted(() => providersRes.fetch());
</script>
