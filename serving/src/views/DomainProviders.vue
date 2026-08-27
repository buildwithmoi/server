<template>
	<AppShell title="Domain Providers" :subtitle="subtitle">
		<template #actions>
			<Button variant="solid" @click="startAdd">
				<template #prefix><Icon name="globe" :size="14" /></template>
				Add provider
			</Button>
		</template>

		<p class="mb-3 max-w-3xl text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			A stored registrar credential lets this app point a domain at this server during
			provisioning, instead of you doing it in the registrar's dashboard and remembering
			to come back. It writes <code class="u-mono">A</code> records and nothing else.
			<b class="text-[var(--ink)]">A DNS record on its own does not make a site serve a
			domain</b> — the domain also has to be added to the site and nginx reloaded, and this
			app will tell you which of those it could not do for you.
		</p>

		<DataTable
			:columns="COLUMNS" :rows="rows" :loading="loading" :total="rows.length" :page-length="50"
			clickable
			empty-title="No providers yet"
			empty-hint="Add one to have domains pointed here automatically."
			@row-click="startEdit"
		>
			<template #cell-provider="{ row }">
				<span>{{ row.provider }}</span>
				<span v-if="row.is_default" class="ml-1.5 text-[11px] text-[var(--ink-faint)]">default</span>
			</template>
			<template #cell-has_token="{ row }">
				<OutcomeMark :outcome="row.has_token ? 'Success' : 'Failure'"
				             :label="row.has_token ? 'token set' : 'no token'" />
			</template>
			<template #cell-zone_count="{ row }">
				<span class="u-num">{{ row.zone_count || 0 }}</span>
				<button class="ml-2 text-[11.5px] text-[var(--ink-faint)] hover:text-[var(--ink)]"
				        :disabled="verifying === row.name" @click.stop="verify(row)">
					{{ verifying === row.name ? "checking…" : "check" }}
				</button>
			</template>
			<template #cell-last_verified_at="{ row }">
				<span class="text-[12px] text-[var(--ink-faint)]">{{ ago(row.last_verified_at) }}</span>
			</template>
			<template #cell-verify_error="{ row }">
				<span v-if="row.verify_error" class="u-danger text-[12px]">{{ row.verify_error }}</span>
				<span v-else-if="row.zones?.length" class="u-mono text-[12px] text-[var(--ink-faint)]">
					{{ row.zones.slice(0, 3).join(", ") }}{{ row.zones.length > 3 ? ` +${row.zones.length - 3}` : "" }}
				</span>
				<span v-else class="text-[12px] text-[var(--ink-faint)]">not checked yet</span>
			</template>
		</DataTable>

		<Dialog v-model="showForm" :options="{ title: editing ? 'Edit provider' : 'Add provider', size: 'lg' }">
			<template #body-content>
				<div class="flex flex-col gap-3.5">
					<div class="grid gap-3 sm:grid-cols-2">
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Name</span>
							<input v-model.trim="form.provider_name" placeholder="Hostinger (main account)"
							       class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
							<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
								Only a label, so you can tell two accounts apart.
							</span>
						</label>
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Provider</span>
							<select v-model="form.provider" :disabled="!!editing"
							        class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)] disabled:opacity-60">
								<option v-for="s in specs" :key="s.name" :value="s.name">{{ s.label }}</option>
							</select>
							<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
								<template v-if="editing">
									Fixed once saved — the stored token belongs to this provider.
								</template>
								<template v-else>Each expects a different kind of credential.</template>
							</span>
						</label>
					</div>

					<!--
						The credential is named as the PROVIDER names it. An
						"API token" and a "Personal Access Token" are found in
						different places in different dashboards, and the wrong
						word sends people hunting through settings pages.
					-->
					<label class="flex flex-col gap-1.5">
						<span class="u-label">{{ spec?.credential_label || "Token" }}</span>
						<input v-model.trim="form.api_token" type="password"
						       :placeholder="editing && tokenSet ? 'unchanged — leave blank to keep it' : 'paste the token'"
						       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
						<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
							{{ spec?.description }}
							Stored encrypted and never sent back to this page.
							<a v-if="spec?.docs_url" :href="spec.docs_url" target="_blank" rel="noreferrer"
							   class="underline underline-offset-2">Where to get one</a>
						</span>
					</label>

					<label class="flex items-center gap-2 text-[12.5px]">
						<input v-model="form.is_default" type="checkbox" class="accent-[var(--ink)]" />
						Pre-select this provider when a domain needs pointing
					</label>

					<p v-if="error" class="flex items-start gap-2 text-[12.5px] leading-relaxed">
						<Icon name="alert" :size="14" class="mt-[2px] shrink-0" />
						<span>{{ error }}</span>
					</p>
				</div>
			</template>
			<template #actions>
				<div class="flex items-center justify-between gap-2">
					<Button v-if="editing" @click="remove">Delete</Button>
					<span v-else />
					<div class="flex gap-2">
						<Button @click="showForm = false">Cancel</Button>
						<Button variant="solid" :loading="saving" :disabled="!canSave" @click="save">Save</Button>
					</div>
				</div>
			</template>
		</Dialog>
	</AppShell>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { Button, Dialog, toast } from "frappe-ui";

import AppShell from "../components/AppShell.vue";
import DataTable from "../components/DataTable.vue";
import Icon from "../components/Icon.vue";
import OutcomeMark from "../components/OutcomeMark.vue";
import {
	deleteDomainProviderResource,
	domainProvidersResource,
	saveDomainProviderResource,
	verifyDomainProviderResource,
} from "../api";

const COLUMNS = [
	{ key: "provider_name", label: "Name", width: "220px" },
	{ key: "provider", label: "Provider", width: "160px" },
	{ key: "has_token", label: "Credential", width: "140px" },
	{ key: "zone_count", label: "Domains", width: "120px" },
	{ key: "last_verified_at", label: "Checked", width: "130px" },
	{ key: "verify_error", label: "Result" },
];

const resource = domainProvidersResource();
const saveResource = saveDomainProviderResource();
const deleteResource = deleteDomainProviderResource();
const verifyResource = verifyDomainProviderResource();

const showForm = ref(false);
const editing = ref("");
const tokenSet = ref(false);
const saving = ref(false);
const verifying = ref("");
const error = ref("");

/** Blank form, so add and edit share one dialog and one shape. */
const blank = () => ({ provider_name: "", provider: "Hostinger", api_token: "", is_default: false });
const form = ref(blank());

const rows = computed(() => resource.data?.providers || []);
const specs = computed(() => resource.data?.specs || []);
const loading = computed(() => resource.loading);
const spec = computed(() => specs.value.find((s) => s.name === form.value.provider));
const canSave = computed(() => !!form.value.provider_name && !!form.value.provider);
const subtitle = computed(() =>
	loading.value && !rows.value.length ? "loading…" : `${rows.value.length} configured`,
);

function ago(value) {
	if (!value) return "never";
	const date = new Date(value.replace(" ", "T"));
	if (Number.isNaN(date.getTime())) return value;
	const minutes = Math.round((Date.now() - date.getTime()) / 60000);
	if (minutes < 60) return `${minutes}m ago`;
	if (minutes < 60 * 24) return `${Math.round(minutes / 60)}h ago`;
	return `${Math.round(minutes / 1440)}d ago`;
}

function startAdd() {
	editing.value = "";
	tokenSet.value = false;
	form.value = blank();
	error.value = "";
	showForm.value = true;
}

function startEdit(row) {
	editing.value = row.name;
	tokenSet.value = !!row.has_token;
	// The token is deliberately absent: the browser never receives it, and an
	// empty field on save means "keep the stored one" rather than "clear it".
	form.value = {
		provider_name: row.provider_name,
		provider: row.provider,
		api_token: "",
		is_default: !!row.is_default,
	};
	error.value = "";
	showForm.value = true;
}

async function save() {
	saving.value = true;
	error.value = "";
	try {
		const result = await saveResource.submit({ ...form.value, name: editing.value || null });
		// Say when the name actually moved. A rename that reports "Saved" and
		// silently did nothing is how this went unnoticed three times.
		toast.success(
			editing.value && result.name !== editing.value
				? `Renamed to ${result.name}`
				: "Saved",
		);
		showForm.value = false;
		resource.fetch();
	} catch (caught) {
		error.value = caught.messages?.[0] || "Could not save this provider.";
	} finally {
		saving.value = false;
	}
}

async function remove() {
	if (!editing.value) return;
	saving.value = true;
	try {
		await deleteResource.submit({ name: editing.value });
		toast.success("Deleted");
		showForm.value = false;
		resource.fetch();
	} catch (caught) {
		error.value = caught.messages?.[0] || "Could not delete this provider.";
	} finally {
		saving.value = false;
	}
}

async function verify(row) {
	verifying.value = row.name;
	try {
		const result = await verifyResource.submit({ name: row.name });
		if (result.ok) {
			toast.success(
				result.zones.length
					? `${result.zones.length} domain${result.zones.length === 1 ? "" : "s"} reachable`
					: "The credential works, but manages no domains",
			);
		} else {
			// Not a toast.error alone: the reason is often long and worth
			// reading, so it also lands in the table's Result column.
			toast.error("The credential did not work");
		}
		resource.fetch();
	} catch (caught) {
		toast.error(caught.messages?.[0] || "Could not check this provider.");
	} finally {
		verifying.value = "";
	}
}

onMounted(() => resource.fetch());
</script>
