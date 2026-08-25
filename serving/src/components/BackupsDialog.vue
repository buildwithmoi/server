<template>
	<Dialog
		v-model="open"
		:options="{ title: `Backups · ${bench}`, size: '2xl' }"
		:disable-outside-click-to-close="busy"
	>
		<template #body-content>
			<div class="flex flex-col gap-3.5">
				<div class="flex flex-col gap-1.5">
					<span class="u-label">Site</span>
					<SearchSelect
						v-model="site"
						:options="siteOptions"
						placeholder="Choose a site"
						search-placeholder="Search sites"
					/>
				</div>

				<div v-if="plan.data" class="flex items-baseline justify-between gap-3">
					<p class="u-item-detail">
						{{ plan.data.candidates.length }}
						{{ plan.data.candidates.length === 1 ? "backup" : "backups" }} ·
						{{ plan.data.total_text }} on disk
					</p>
					<Button size="sm" :loading="backingUp" @click="backupNow">
						<template #prefix><Icon name="database" :size="13" /></template>
						Back up now
					</Button>
				</div>

				<!--
					The rules are the module's, not the dialog's, and they are stated
					here because "why can't I delete that one" is the first question
					anyone asks. Nothing in the newest few goes, and nothing under a
					day old goes — clearing space is usually something you do right
					before a restore.
				-->
				<div class="flex flex-wrap items-end gap-3 rounded-md border border-[var(--rule)] px-3 py-2.5">
					<label class="flex flex-col gap-1">
						<span class="u-label">Keep the newest</span>
						<select
							v-model.number="keep"
							class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
						>
							<option v-for="n in [2, 3, 5, 10, 20]" :key="n" :value="n">{{ n }}</option>
						</select>
					</label>
					<label class="flex flex-col gap-1">
						<span class="u-label">Older than</span>
						<select
							v-model.number="olderThan"
							class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
						>
							<option :value="0">any age</option>
							<option v-for="n in [7, 14, 30, 90]" :key="n" :value="n">{{ n }} days</option>
						</select>
					</label>
					<p class="u-item-detail min-w-[160px] flex-1">
						Both must be true before a backup is offered for deletion. Nothing under a
						day old is ever removed.
					</p>
				</div>

				<div v-if="plan.loading" class="flex items-center gap-2 py-2">
					<Spinner class="h-3.5 w-3.5 text-[var(--ink-faint)]" />
					<span class="u-item-detail">Reading the backup directory…</span>
				</div>

				<ul v-else-if="candidates.length" class="flex flex-col gap-1">
					<li
						v-for="row in candidates"
						:key="row.key"
						class="flex items-center gap-2.5 rounded-md border px-2.5 py-2"
						:class="row.deletable ? 'border-[var(--danger-border)] bg-[var(--danger-bg)]' : 'border-[var(--rule)]'"
					>
						<Icon
							:name="row.deletable ? 'trash' : 'lock'"
							:size="13"
							class="shrink-0"
							:class="row.deletable ? 'u-danger' : 'text-[var(--ink-ghost)]'"
						/>
						<span class="min-w-0 flex-1">
							<span class="u-item-label block truncate">{{ row.taken_at }}</span>
							<span class="u-item-detail block truncate">{{ row.reason }}</span>
						</span>
						<span class="u-item-detail shrink-0 tabular-nums">{{ row.age_text }}</span>
						<span class="u-chip shrink-0">{{ row.size_text }}</span>
					</li>
				</ul>

				<p v-else class="u-item-detail py-2">This site has no backups yet.</p>

				<div v-if="deletable.length" class="u-note u-note-danger flex flex-col gap-2">
					<div class="flex items-start gap-2.5">
						<Icon name="alert" :size="15" class="u-danger mt-0.5 shrink-0" />
						<p class="text-[12.5px] leading-relaxed">
							{{ deletable.length }}
							{{ deletable.length === 1 ? "backup" : "backups" }} would be deleted,
							freeing {{ plan.data.freed_text }}. This cannot be undone — a deleted
							backup is gone.
						</p>
					</div>
					<label class="flex cursor-pointer items-center gap-2.5">
						<input v-model="confirmed" type="checkbox" />
						<span class="u-item-detail">I understand these cannot be recovered.</span>
					</label>
				</div>

				<p v-if="warning" class="u-note u-note-warn flex items-start gap-2.5">
					<Icon name="alert" :size="15" class="u-warn mt-0.5 shrink-0" />
					<span class="text-[12.5px] leading-relaxed">{{ warning }}</span>
				</p>

				<p v-if="error" class="flex items-start gap-2 text-[12.5px] leading-relaxed">
					<Icon name="alert" :size="14" class="u-danger mt-[2px] shrink-0" />
					<span>{{ error }}</span>
				</p>
			</div>
		</template>

		<template #actions>
			<div class="flex justify-end gap-2">
				<Button @click="open = false">Close</Button>
				<Button
					variant="solid"
					theme="red"
					:loading="pruning"
					:disabled="!deletable.length || !confirmed"
					@click="prune"
				>
					Delete {{ deletable.length || "" }}
				</Button>
			</div>
		</template>
	</Dialog>
</template>

<script setup>
import { computed, ref, watch } from "vue";
import { Button, Dialog, Spinner, toast } from "frappe-ui";
import Icon from "./Icon.vue";
import SearchSelect from "./SearchSelect.vue";
import { watchJob } from "../jobs";
import { useBusyGuard } from "../busy";
import { backupPlanResource, pruneBackupsResource, runBenchCommandResource } from "../api";

const props = defineProps({
	modelValue: { type: Boolean, default: false },
	bench: { type: String, required: true },
	sites: { type: Array, default: () => [] },
	defaultSite: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue", "started"]);

const plan = backupPlanResource();
const site = ref(null);
const keep = ref(5);
const olderThan = ref(0);
const confirmed = ref(false);
const pruning = ref(false);
const backingUp = ref(false);
const error = ref("");
const warning = ref("");

// Closing mid-flight loses the work — the dialog owns it, and there is no
// job card to come back to. See busy.ts.
const busy = computed(() => pruning.value || backingUp.value);
useBusyGuard(busy);

const open = computed({
	get: () => props.modelValue,
	set: (v) => emit("update:modelValue", v),
});

const siteOptions = computed(() =>
	props.sites.map((s) => ({
		label: s,
		value: s,
		description: s === props.defaultSite ? "Default site for this bench" : "",
	})),
);

const candidates = computed(() => plan.data?.candidates || []);
const deletable = computed(() => candidates.value.filter((c) => c.deletable));

function load() {
	if (!site.value?.value) return;
	confirmed.value = false;
	warning.value = "";
	plan.fetch({
		bench: props.bench,
		site: site.value.value,
		keep: keep.value,
		older_than_days: olderThan.value,
	});
}

async function backupNow() {
	backingUp.value = true;
	error.value = "";
	try {
		const result = await runBenchCommandResource().submit({
			bench: props.bench,
			command: "site.backup",
			site: site.value.value,
		});
		watchJob(result.name, {
			operation: "Command",
			app_name: `Backup · ${site.value.value}`,
			bench: props.bench,
			status: "Queued",
		});
		toast.success("Backup started");
		emit("started", result.name);
	} catch (err) {
		error.value = err.messages?.[0] || err.message || "Could not start the backup";
	} finally {
		backingUp.value = false;
	}
}

async function prune() {
	pruning.value = true;
	error.value = "";
	try {
		const result = await pruneBackupsResource().submit({
			bench: props.bench,
			site: site.value.value,
			keys: deletable.value.map((c) => c.key),
			keep: keep.value,
			confirm: 1,
		});
		// Report what actually happened, not what was asked for. This used to
		// count every target as deleted including the ones the guard refused,
		// so the operator was told gigabytes had been freed while the disk
		// alert fired again an hour later.
		const skipped = (result.failed?.length || 0) + (result.refused?.length || 0);
		if (skipped) {
			warning.value =
				`${result.deleted_sets.length} deleted, freeing ${result.freed_text}. ` +
				`${skipped} could not be removed — reopen this dialog to see what is left.`;
			toast.error(warning.value);
		} else {
			warning.value = "";
			toast.success(
				`Deleted ${result.deleted_sets.length}, freeing ${result.freed_text}`,
			);
		}
		// The server recomputes its own plan, so re-read rather than assuming
		// what went — a scheduled backup may have landed in between.
		load();
	} catch (err) {
		error.value = err.messages?.[0] || err.message || "Could not delete the backups";
	} finally {
		pruning.value = false;
	}
}

watch(
	() => props.modelValue,
	(isOpen) => {
		if (!isOpen) return;
		error.value = "";
		if (!site.value) {
			const preferred = props.defaultSite || props.sites[0];
			if (preferred) site.value = { label: preferred, value: preferred };
		}
		load();
	},
);

watch([site, keep, olderThan], load);
</script>
