<template>
	<Dialog
		v-model="open"
		:options="{ title: 'Move a bench here', size: '3xl' }"
		:disable-outside-click-to-close="busy"
	>
		<template #body-content>
			<div class="flex flex-col gap-3.5">
				<p class="text-[12.5px] leading-relaxed text-[var(--ink-faint)]">
					Takes every site on a bench elsewhere and brings it here — building the bench and
					cloning its apps first if they are not already present. Each step runs as its own
					job, so you can watch them, stop one, and continue where it stopped.
				</p>

				<div class="grid gap-3 sm:grid-cols-3">
					<div class="flex flex-col gap-1.5">
						<span class="u-label">From server</span>
						<select v-model="form.server" @change="onServer"
						        class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-[7px] text-[13px] outline-none focus:border-[var(--ink)]">
							<option value="" disabled>choose</option>
							<option v-for="s in servers" :key="s.name" :value="s.name">{{ s.server_name }}</option>
						</select>
					</div>
					<div class="flex flex-col gap-1.5">
						<span class="u-label">Bench there</span>
						<SearchSelect v-model="form.bench" :options="benchOptions" mono
						              placeholder="Choose a bench" :loading="benches.loading"
						              :disabled="!form.server" />
					</div>
					<div class="flex flex-col gap-1.5">
						<span class="u-label">Bench here</span>
						<input v-model.trim="form.target" :placeholder="form.bench?.value || 'same name'"
						       class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-[7px] text-[13px] outline-none focus:border-[var(--ink)]" />
					</div>
				</div>

				<p v-if="!servers.length" class="u-item-detail">
					No other servers are registered. Add one under Masters → Servers first.
				</p>

				<div v-if="planning" class="flex items-center gap-2 text-[13px] text-[var(--ink-faint)]">
					<Spinner class="h-3.5 w-3.5" /> Working out what this would involve…
				</div>

				<!--
					The plan, before anything runs. This is the whole reason the
					feature is split into plan-then-do: moving eight benches is
					hours of work, and the useful thing is seeing what will be
					built and what is missing BEFORE any of it starts.
				-->
				<template v-else-if="plan">
					<div class="rounded-lg border border-[var(--rule)]">
						<header class="border-b border-[var(--rule)] px-3 py-2 text-[12.5px]">
							{{ plan.bench_exists
								? `${plan.target_bench} is already here`
								: `${plan.target_bench} will be built first, on frappe version-${plan.frappe_version}` }}
						</header>

						<div v-if="plan.apps.length" class="border-b border-[var(--rule)] px-3 py-2">
							<p class="u-label mb-1.5">Apps</p>
							<ul class="flex flex-col gap-1">
								<li v-for="a in plan.apps" :key="a.app_name"
								    class="flex flex-wrap items-center gap-2 text-[12.5px]">
									<Icon :name="a.present ? 'check' : 'download'" :size="13"
									      :class="a.present ? 'u-ok' : ''" class="shrink-0" />
									<span class="u-mono">{{ a.app_name }}</span>
									<span class="text-[var(--ink-faint)]">{{ a.branch }}</span>
									<span class="ml-auto text-[11.5px]"
									      :class="a.action === 'check branch' ? 'text-[var(--warn)]' : 'text-[var(--ink-faint)]'">
										{{ a.action }}
									</span>
								</li>
							</ul>
						</div>

						<div class="px-3 py-2">
							<p class="u-label mb-1.5">Sites, in the order they move</p>
							<ul v-if="plan.order.length" class="flex flex-col gap-1.5">
								<li v-for="(name, i) in plan.order" :key="name"
								    class="flex flex-wrap items-center gap-2 text-[12.5px]">
									<span class="w-4 shrink-0 text-[11px] text-[var(--ink-faint)]">{{ i + 1 }}</span>
									<span class="u-mono">{{ name }}</span>
									<span class="text-[var(--ink-faint)]">→</span>
									<!--
										Editable, because moving a site onto a
										machine that already runs it means
										bringing it up beside the live one under
										another name, checking it, and swapping
										later. Same name = restore in place.
									-->
									<input
										v-model.trim="form.renames[name]"
										:placeholder="name"
										class="u-mono min-w-0 flex-1 rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1 text-[12px] outline-none focus:border-[var(--ink)]"
									/>
									<span class="shrink-0 text-[11.5px]"
									      :class="actionFor(name) === 'replace' ? 'text-[var(--danger)]' : 'text-[var(--ink-faint)]'">
										{{ actionFor(name) }}
									</span>
								</li>
							</ul>
							<p v-if="plan.order.length" class="u-item-detail mt-2">
								Leave a name as it is to restore in place. Change it and the site is created
								under the new name instead, and nothing here is touched.
							</p>
							<p v-else class="u-item-detail">That bench has no sites.</p>
						</div>
					</div>

					<p v-for="note in plan.notes" :key="note"
					   class="u-note text-[12.5px] leading-relaxed"
					   :class="note.includes('REPLACED') ? 'u-note-danger' : ''">
						{{ note }}
					</p>

					<div class="grid gap-3 sm:grid-cols-2">
						<label class="flex items-start gap-2 text-[13px]">
							<input v-model="form.withFiles" type="checkbox" class="mt-[3px]" />
							<span>
								Move files as well
								<span class="u-item-detail block">
									Attachments and private files. Off is much faster and loses them.
								</span>
							</span>
						</label>
						<label class="flex items-start gap-2 text-[13px]">
							<input v-model="form.backupFirst" type="checkbox" class="mt-[3px]" />
							<span>
								Back up before replacing
								<span class="u-item-detail block">
									Only affects sites that already exist here. A new site has nothing to back up.
								</span>
							</span>
						</label>
					</div>

					<label class="flex flex-col gap-1.5">
						<span class="u-label">Database root password</span>
						<input v-model="form.password" type="password" autocomplete="new-password"
						       placeholder="needed to create and restore each site"
						       class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-[7px] text-[13px] outline-none focus:border-[var(--ink)]" />
						<span class="u-item-detail">
							Held for the length of the migration and cleared when it ends, however it ends.
						</span>
					</label>

					<div class="u-note u-note-danger flex flex-col gap-2 text-[12.5px] leading-relaxed">
						<span>
							This runs for as long as it takes — {{ plan.order.length }} site(s), each backed up
							on {{ plan.source_server }}, copied here and restored. Type
							<span class="u-mono">{{ plan.target_bench }}</span> to confirm.
						</span>
						<input v-model.trim="form.confirm" type="text" autocomplete="off"
						       :placeholder="plan.target_bench"
						       class="w-56 rounded-md border border-[var(--danger-border)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]" />
					</div>
				</template>

				<p v-if="error" class="flex items-start gap-2 text-[12.5px] leading-relaxed">
					<Icon name="alert" :size="14" class="mt-[2px] shrink-0" />
					<span>{{ error }}</span>
				</p>
			</div>
		</template>

		<template #actions>
			<div class="flex items-center justify-end gap-2">
				<Button :disabled="busy" @click="open = false">Cancel</Button>
				<Button variant="solid" :loading="starting" :disabled="!canStart" @click="start">
					Start the move
				</Button>
			</div>
		</template>
	</Dialog>
</template>

<script setup>
import { computed, reactive, ref, watch } from "vue";
import { Button, Dialog, Spinner, toast } from "frappe-ui";

import Icon from "./Icon.vue";
import SearchSelect from "./SearchSelect.vue";
import {
	callRemoteResource,
	managedServersResource,
	planMigrationResource,
	startMigrationResource,
} from "../api";

const props = defineProps({ modelValue: { type: Boolean, default: false } });
const emit = defineEmits(["update:modelValue", "started"]);

const serversRes = managedServersResource();
const benches = callRemoteResource();
const planRes = planMigrationResource();
const startRes = startMigrationResource();

const form = reactive({
	server: "",
	bench: null,
	target: "",
	withFiles: true,
	backupFirst: true,
	password: "",
	confirm: "",
	//: {source site: name to restore it as}. Empty or unchanged means "in place".
	renames: {},
});
const starting = ref(false);
const error = ref("");

const open = computed({
	get: () => props.modelValue,
	set: (v) => emit("update:modelValue", v),
});

// Only servers that answered. Offering an unreachable one produces a plan
// request that fails at the first call.
const servers = computed(() =>
	(serversRes.data || []).filter((s) => !s.is_this_server && s.status === "Reachable"),
);

const benchOptions = computed(() =>
	(benches.data?.message || []).map((b) => ({
		value: b.name,
		label: b.name,
		description: `${(b.sites || []).length} site(s) · frappe ${b.frappe_branch || "?"}`,
	})),
);

const plan = computed(() => planRes.data);
const planning = computed(() => planRes.loading);
const busy = computed(() => starting.value || planning.value);

const canStart = computed(
	() =>
		Boolean(plan.value) &&
		Boolean(form.password) &&
		form.confirm === plan.value?.target_bench &&
		!busy.value,
);

const siteAction = (name) =>
	(plan.value?.sites || []).find((s) => s.site_name === name)?.action || "";

/**
 * What will happen to a site, allowing for a rename.
 *
 * A renamed target is by definition not here, so it is created — even when a
 * site of the ORIGINAL name is, which is exactly the case this exists for.
 */
function actionFor(name) {
	const target = (form.renames[name] || "").trim();
	if (target && target !== name) return "create then restore";
	return siteAction(name);
}

function onServer() {
	form.bench = null;
	planRes.reset?.();
	if (!form.server) return;
	benches
		.submit({ server: form.server, method: "server.api.list_benches", args: {} })
		.catch((e) => (error.value = e.messages?.[0] || "Could not read that server"));
}

// The plan is rebuilt whenever the target changes, because "already here" is
// the answer that decides whether a bench gets built and whether a site is
// replaced rather than created.
watch(
	() => [form.server, form.bench?.value, form.target],
	() => {
		error.value = "";
		planRes.reset?.();
		if (!form.server || !form.bench?.value) return;
		planRes
			.submit({
				server: form.server,
				remote_bench: form.bench.value,
				target_bench: form.target || form.bench.value,
			})
			.catch((e) => (error.value = e.messages?.[0] || "Could not work out a plan"));
	},
);

async function start() {
	starting.value = true;
	error.value = "";
	try {
		const result = await startRes.submit({
			server: form.server,
			remote_bench: form.bench.value,
			target_bench: plan.value.target_bench,
			db_root_password: form.password,
			with_files: form.withFiles ? 1 : 0,
			backup_first: form.backupFirst ? 1 : 0,
			confirm: form.confirm,
			// Only the ones actually changed. An untouched field is an empty
			// string, and sending those would look like a rename to nothing.
			renames: Object.fromEntries(
				Object.entries(form.renames).filter(([from, to]) => to && to.trim() && to.trim() !== from),
			),
		});
		toast.success(`${result.actions} step(s) queued`);
		open.value = false;
		emit("started", result.name);
	} catch (caught) {
		error.value = caught.messages?.[0] || "Could not start the move.";
	} finally {
		starting.value = false;
		// Never left in the component after the call, migration started or not.
		form.password = "";
	}
}

watch(
	() => props.modelValue,
	(isOpen) => {
		if (isOpen) {
			serversRes.fetch();
			return;
		}
		Object.assign(form, {
			server: "", bench: null, target: "", withFiles: true,
			backupFirst: true, password: "", confirm: "",
		});
		planRes.reset?.();
		error.value = "";
	},
);
</script>
