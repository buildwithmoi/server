<template>
	<AppShell title="Servers" :subtitle="subtitle">
		<template #actions>
			<Button variant="solid" @click="startAdd">
				<template #prefix><Icon name="server" :size="14" /></template>
				Add a server
			</Button>
		</template>

		<p class="mb-4 text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
			Other machines running this app. Switching to one shows its benches, its findings and
			its history here, without logging in separately — this server forwards the calls, so
			the credentials below never reach your browser.
		</p>

		<div v-if="loading && !rows.length" class="space-y-2">
			<Skeleton v-for="n in 3" :key="n" class="h-20" />
		</div>

		<EmptyState
			v-else-if="!rows.length"
			title="No servers yet"
			hint="Add the machine you are on first, then the others. Each needs an API key and secret from a System Manager account there."
		/>

		<ul v-else class="space-y-2">
			<li
				v-for="row in rows"
				:key="row.name"
				class="rounded-lg border bg-[var(--paper)] p-3"
				:class="row.name === currentServer
					? 'border-[var(--ink)]'
					: 'border-[var(--rule)] hover:border-[var(--rule-strong)]'"
			>
				<div class="flex flex-wrap items-start gap-3">
					<span class="mt-[5px] h-[7px] w-[7px] shrink-0 rounded-full" :class="dot(row)" />
					<div class="min-w-0 flex-1">
						<p class="flex flex-wrap items-baseline gap-2 text-[13.5px]">
							<span>{{ row.server_name }}</span>
							<span v-if="row.is_this_server" class="u-chip">this machine</span>
							<span v-if="row.name === currentServer && !row.is_this_server" class="u-chip">viewing</span>
						</p>
						<p class="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11.5px] text-[var(--ink-faint)]">
							<span class="u-mono">{{ row.base_url }}</span>
							<span>{{ row.status.toLowerCase() }}</span>
							<span v-if="row.remote_hostname" class="u-mono">{{ row.remote_hostname }}</span>
							<span v-if="row.last_verified_at">checked {{ ago(row.last_verified_at) }}</span>
							<!-- Said out loud rather than left to the doctype: this
							     connection carries a database. -->
							<span v-if="!row.verify_tls && !row.is_this_server" class="text-[var(--warn)]">
								TLS not verified
							</span>
							<span v-if="!row.has_secret && !row.is_this_server" class="text-[var(--warn)]">
								no secret stored
							</span>
						</p>
						<p v-if="row.verify_error" class="mt-1 text-[12px] text-[var(--danger)]">
							{{ row.verify_error }}
						</p>
					</div>

					<div class="flex shrink-0 flex-wrap items-center gap-2">
						<Button
							v-if="row.name !== currentServer"
							variant="subtle"
							:disabled="!row.is_this_server && row.status !== 'Reachable'"
							:title="!row.is_this_server && row.status !== 'Reachable' ? 'Check it first' : ''"
							@click="switchTo(row)"
						>
							{{ row.is_this_server ? "Back to local" : "Switch to it" }}
						</Button>
						<Button variant="ghost" :loading="checking === row.name" @click="check(row)">Check</Button>
						<Button variant="ghost" @click="startEdit(row)">Edit</Button>
					</div>
				</div>
			</li>
		</ul>

		<Dialog v-model="showForm" :options="{ title: editing ? 'Edit server' : 'Add a server', size: 'xl' }">
			<template #body-content>
				<div class="flex flex-col gap-3.5">
					<label class="flex flex-col gap-1.5">
						<span class="u-label">Name</span>
						<input v-model.trim="form.server_name" :disabled="!!editing" placeholder="hetzner-prod"
						       class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-[7px] text-[13px] outline-none focus:border-[var(--ink)] disabled:opacity-60" />
						<span class="u-item-detail">What you will call it in the switcher.</span>
					</label>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">Address</span>
						<input v-model.trim="form.base_url" placeholder="https://server2.example.com"
						       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-[7px] text-[13px] outline-none focus:border-[var(--ink)]" />
						<span class="u-item-detail">Include the scheme, and the port if it is not 443.</span>
					</label>

					<label class="flex items-start gap-2 text-[13px]">
						<input v-model="form.is_this_server" type="checkbox" class="mt-[3px]" />
						<span>
							This is the machine I am on
							<span class="u-item-detail block">
								Listed so the switcher can offer a way back. It is never called over the network,
								so it needs no key.
							</span>
						</span>
					</label>

					<template v-if="!form.is_this_server">
						<div class="grid gap-3 sm:grid-cols-2">
							<label class="flex flex-col gap-1.5">
								<span class="u-label">API key</span>
								<input v-model.trim="form.api_key" placeholder="from the remote's User record"
								       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-[7px] text-[13px] outline-none focus:border-[var(--ink)]" />
							</label>
							<label class="flex flex-col gap-1.5">
								<span class="u-label">API secret</span>
								<input v-model="form.api_secret" type="password" autocomplete="new-password"
								       :placeholder="editing && secretSet ? 'unchanged — leave blank to keep it' : 'paste the secret'"
								       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-[7px] text-[13px] outline-none focus:border-[var(--ink)]" />
							</label>
						</div>
						<p class="u-item-detail -mt-1">
							Give the remote its own System Manager account rather than reusing yours, so it can
							be revoked without locking anybody out. The secret is stored encrypted and is never
							sent back to this page.
						</p>

						<label class="flex items-start gap-2 text-[13px]">
							<input v-model="form.verify_tls" type="checkbox" class="mt-[3px]" />
							<span>
								Verify its TLS certificate
								<span class="u-item-detail block">
									Leave on. Turn it off only for a server that has no certificate yet — common on
									one you have just provisioned, which is exactly when you would be moving sites
									onto it. Unverified traffic can be read and altered, and this carries backups.
								</span>
							</span>
						</label>
					</template>

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
						<Button variant="solid" :loading="saving" @click="save">Save</Button>
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
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import Skeleton from "../components/Skeleton.vue";
import { currentServer, switchToServer } from "../state";
import {
	deleteManagedServerResource,
	managedServersResource,
	saveManagedServerResource,
	verifyManagedServerResource,
} from "../api";

const resource = managedServersResource();
const saveResource = saveManagedServerResource();
const deleteResource = deleteManagedServerResource();
const verifyResource = verifyManagedServerResource();

const showForm = ref(false);
const editing = ref("");
const secretSet = ref(false);
const saving = ref(false);
const checking = ref("");
const error = ref("");

const blank = () => ({
	server_name: "",
	base_url: "",
	api_key: "",
	api_secret: "",
	verify_tls: true,
	is_this_server: false,
});
const form = ref(blank());

const rows = computed(() => resource.data || []);
const loading = computed(() => resource.loading);

const subtitle = computed(() => {
	if (loading.value && !rows.value.length) return "loading…";
	const reachable = rows.value.filter((r) => r.status === "Reachable" || r.is_this_server).length;
	return `${rows.value.length} registered · ${reachable} reachable`;
});

const DOTS = { Reachable: "bg-[var(--ok)]", Unreachable: "bg-[var(--danger)]", Refused: "bg-[var(--danger)]" };
const dot = (row) => (row.is_this_server ? "bg-[var(--ok)]" : DOTS[row.status] || "bg-[var(--ink-ghost)]");

function ago(value) {
	if (!value) return "never";
	const date = new Date(value.replace(" ", "T"));
	if (Number.isNaN(date.getTime())) return value;
	const minutes = Math.round((Date.now() - date.getTime()) / 60000);
	if (minutes < 1) return "just now";
	if (minutes < 60) return `${minutes}m ago`;
	if (minutes < 1440) return `${Math.round(minutes / 60)}h ago`;
	return `${Math.round(minutes / 1440)}d ago`;
}

function startAdd() {
	editing.value = "";
	secretSet.value = false;
	form.value = blank();
	error.value = "";
	showForm.value = true;
}

function startEdit(row) {
	editing.value = row.name;
	secretSet.value = row.has_secret;
	form.value = {
		server_name: row.server_name,
		base_url: row.base_url,
		api_key: row.api_key || "",
		// Never prefilled: the server does not send it, and a masked value in
		// the box would be indistinguishable from a real one on save.
		api_secret: "",
		verify_tls: Boolean(row.verify_tls),
		is_this_server: Boolean(row.is_this_server),
	};
	error.value = "";
	showForm.value = true;
}

async function save() {
	saving.value = true;
	error.value = "";
	try {
		await saveResource.submit({ ...form.value, name: editing.value || null });
		showForm.value = false;
		await resource.fetch();
		toast.success("Saved");
	} catch (caught) {
		error.value = caught.messages?.[0] || "Could not save that.";
	} finally {
		saving.value = false;
	}
}

async function remove() {
	try {
		await deleteResource.submit({ name: editing.value });
		if (currentServer.value === editing.value) switchToServer("");
		showForm.value = false;
		await resource.fetch();
		toast.success("Removed");
	} catch (caught) {
		error.value = caught.messages?.[0] || "Could not remove it.";
	}
}

async function check(row) {
	checking.value = row.name;
	try {
		const result = await verifyResource.submit({ name: row.name });
		if (result.ok) toast.success(`${row.server_name} answered as ${result.identity?.hostname || "itself"}`);
		else toast.error(result.error || "It did not answer");
		await resource.fetch();
	} catch (caught) {
		toast.error(caught.messages?.[0] || "Could not reach it");
	} finally {
		checking.value = "";
	}
}

function switchTo(row) {
	// The local row switches back rather than "to": there is nothing to
	// forward to a machine you are already on.
	switchToServer(row.is_this_server ? "" : row.name);
	toast.success(row.is_this_server ? "Back to this server" : `Now showing ${row.server_name}`);
}

onMounted(() => resource.fetch());
</script>
