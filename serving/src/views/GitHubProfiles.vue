<template>
	<AppShell title="GitHub Accounts" :subtitle="subtitle">
		<template #actions>
			<Button variant="solid" @click="startAdd">
				<template #prefix><Icon name="key" :size="14" /></template>
				Add account
			</Button>
		</template>

		<p class="mb-3 max-w-3xl text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			An account lets you pick repositories by name when installing, instead of typing URLs.
			Listing <em>private</em> repositories needs a personal access token with the
			<code class="u-mono">repo</code> scope — an SSH key authenticates git, it cannot query
			GitHub's API. Cloning still uses your SSH key; the token is only ever used to read the
			repository and branch lists.
		</p>

		<DataTable
			:columns="COLUMNS" :rows="rows" :loading="loading" :total="rows.length" :page-length="50"
			clickable
			empty-title="No accounts yet"
			empty-hint="Add one to browse repositories when installing an app."
			@row-click="startEdit"
		>
			<template #cell-account="{ row }">
				<span class="u-mono">{{ row.account }}</span>
				<span class="ml-1.5 text-[11px] text-[var(--ink-faint)]">{{ row.account_type }}</span>
			</template>
			<template #cell-has_token="{ row }">
				<OutcomeMark :outcome="row.has_token ? 'Success' : 'Info'"
				             :label="row.has_token ? 'token set' : 'public only'" />
			</template>
			<template #cell-repo_count="{ row }">
				<span class="u-num">{{ row.repo_count || 0 }}</span>
				<button class="ml-2 text-[11.5px] text-[var(--ink-faint)] hover:text-[var(--ink)]"
				        :disabled="syncing === row.name" @click.stop="sync(row)">
					{{ syncing === row.name ? "syncing…" : "sync" }}
				</button>
			</template>
			<template #cell-sync_error="{ row }">
				<span v-if="row.sync_error" class="text-[12px]">{{ row.sync_error }}</span>
				<span v-else class="text-[var(--ink-ghost)]">—</span>
			</template>
		</DataTable>

		<Dialog v-model="showForm" :options="{ title: editing ? `Edit ${editing}` : 'Add GitHub account', size: 'lg' }">
			<template #body-content>
				<div class="flex flex-col gap-3.5">
					<label class="flex flex-col gap-1.5">
						<span class="u-label">Label</span>
						<input v-model.trim="form.profile_name" placeholder="Carbonite"
						       class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
						<span class="text-[11.5px] text-[var(--ink-faint)]">A name for you, shown when picking an account.</span>
					</label>

					<div class="grid gap-3 sm:grid-cols-2">
						<label class="flex flex-col gap-1.5">
							<span class="u-label">GitHub account</span>
							<input v-model.trim="form.account" placeholder="Carbonite-Solutions-Ltd"
							       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
							<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
								Exactly as it appears in a repository URL — not an email address.
							</span>
						</label>
						<label class="flex flex-col gap-1.5">
							<span class="u-label">Account type</span>
							<select v-model="form.account_type" class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]">
								<option>Organisation</option>
								<option>User</option>
							</select>
							<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
								Different API endpoints — the wrong one returns nothing.
							</span>
						</label>
					</div>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">Access token</span>
						<input v-model.trim="form.access_token" type="password"
						       :placeholder="editing && tokenSet ? 'unchanged — leave blank to keep it' : 'ghp_… (optional)'"
						       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
						<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
							Needed only to list private repositories. Stored encrypted and never sent
							back to this page.
						</span>
					</label>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">SSH host alias</span>
						<input v-model.trim="form.ssh_host_alias" placeholder="github-carbonite (optional)"
						       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
						<span class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
							If ~/.ssh/config defines a Host block for this account, naming it here pins
							the right key when cloning. Ignored if the alias does not exist.
						</span>
					</label>

					<label class="flex items-center gap-2 text-[12.5px]">
						<input v-model="form.is_default" type="checkbox" class="accent-[var(--ink)]" />
						Pre-select this account when installing
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
	deleteGithubProfileResource, githubProfilesResource,
	saveGithubProfileResource, syncGithubProfileResource,
} from "../api";

const COLUMNS = [
	{ key: "name", label: "Label", width: "180px" },
	{ key: "account", label: "GitHub account", width: "260px" },
	{ key: "has_token", label: "Access", width: "150px" },
	{ key: "repo_count", label: "Repos", width: "130px" },
	{ key: "ssh_host_alias", label: "SSH alias", mono: true, muted: true, width: "170px" },
	{ key: "sync_error", label: "Last sync", muted: true },
];

const resource = githubProfilesResource();
const showForm = ref(false);
const editing = ref("");
const tokenSet = ref(false);
const saving = ref(false);
const syncing = ref("");
const error = ref("");

const blank = () => ({
	profile_name: "", account: "", account_type: "Organisation",
	access_token: "", ssh_host_alias: "", is_default: false,
});
const form = ref(blank());

const rows = computed(() => resource.data || []);
const loading = computed(() => resource.loading && !resource.data);
const subtitle = computed(() =>
	loading.value ? "loading…" : `${rows.value.length} configured`,
);
const canSave = computed(() => Boolean(form.value.profile_name && form.value.account));

function startAdd() {
	editing.value = "";
	tokenSet.value = false;
	form.value = blank();
	error.value = "";
	showForm.value = true;
}

function startEdit(row) {
	editing.value = row.name;
	tokenSet.value = row.has_token;
	// The token is deliberately absent — the API never returns it, and an empty
	// field on save means "keep the existing one" rather than "clear it".
	form.value = {
		profile_name: row.name, account: row.account, account_type: row.account_type,
		access_token: "", ssh_host_alias: row.ssh_host_alias || "",
		is_default: Boolean(row.is_default),
	};
	error.value = "";
	showForm.value = true;
}

async function save() {
	saving.value = true;
	error.value = "";
	try {
		await saveGithubProfileResource().submit({ ...form.value, name: editing.value || null });
		toast.success(editing.value ? "Account updated" : "Account added");
		showForm.value = false;
		resource.fetch();
	} catch (err) {
		error.value = err.messages?.[0] || err.message || "Could not save";
	} finally {
		saving.value = false;
	}
}

async function remove() {
	try {
		await deleteGithubProfileResource().submit({ name: editing.value });
		toast.success(`${editing.value} removed`);
		showForm.value = false;
		resource.fetch();
	} catch (err) {
		error.value = err.messages?.[0] || "Could not delete";
	}
}

async function sync(row) {
	syncing.value = row.name;
	try {
		const result = await syncGithubProfileResource().submit({ name: row.name });
		if (result.ok) {
			toast.success(`${result.count} repositories cached (${result.private} private)`);
		} else {
			toast.error(result.error);
		}
		resource.fetch();
	} catch (err) {
		toast.error(err.messages?.[0] || "Sync failed");
	} finally {
		syncing.value = "";
	}
}

onMounted(() => resource.fetch());
</script>
