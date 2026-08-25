<template>
	<Dialog v-model="open" :options="{ title: `Site config · ${bench}`, size: '2xl' }">
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

				<div v-if="config.loading" class="flex items-center gap-2 py-2">
					<Spinner class="h-3.5 w-3.5 text-[var(--ink-faint)]" />
					<span class="u-item-detail">Reading site_config.json…</span>
				</div>

				<template v-else-if="config.data">
					<div class="flex items-center gap-1 border-b border-[var(--rule)]">
						<button
							v-for="tab in TABS"
							:key="tab"
							type="button"
							class="border-b-2 px-3 py-1.5 text-[13px] transition-colors duration-150"
							:class="
								view === tab
									? 'border-[var(--ink)] font-medium text-[var(--ink)]'
									: 'border-transparent text-[var(--ink-faint)] hover:text-[var(--ink)]'
							"
							@click="view = tab"
						>{{ tab }}</button>
					</div>

					<!-- Settings: a curated list, each with what it does. Everything
					     else stays the business of `bench set-config`, where a typo is
					     at least deliberate. -->
					<div v-if="view === 'Settings'" class="flex flex-col gap-2">
						<div
							v-for="setting in config.data.editable"
							:key="setting.key"
							class="rounded-md border px-3 py-2.5"
							:class="dirty[setting.key] !== undefined ? 'border-[var(--ink)]' : 'border-[var(--rule)]'"
						>
							<div class="flex items-start justify-between gap-3">
								<div class="min-w-0 flex-1">
									<div class="flex items-center gap-2">
										<span class="u-item-label">{{ setting.label }}</span>
										<span v-if="setting.disruptive" class="u-chip u-chip-warn shrink-0">
											takes the site off the air
										</span>
									</div>
									<p class="u-item-detail mt-1 leading-relaxed">{{ setting.description }}</p>
									<p class="u-mono mt-1 text-[11px] text-[var(--ink-ghost)]">{{ setting.key }}</p>
								</div>

								<div class="shrink-0 pt-0.5">
									<input
										v-if="setting.kind === 'bool'"
										type="checkbox"
										:checked="current(setting)"
										@change="stage(setting, $event.target.checked)"
									/>
									<input
										v-else
										:value="current(setting) ?? ''"
										:placeholder="setting.kind === 'int' ? 'unset' : 'unset'"
										:class="setting.kind === 'int' ? 'w-24 text-right' : 'w-56'"
										class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1 text-[13px] outline-none focus:border-[var(--ink)]"
										@change="stage(setting, $event.target.value)"
									/>
								</div>
							</div>
						</div>
					</div>

					<!-- Everything as it is on disk, secrets shown as present and
					     nothing more. -->
					<div v-else class="overflow-hidden rounded-md border border-[var(--rule)]">
						<div
							v-for="row in config.data.values"
							:key="row.key"
							class="flex items-baseline gap-3 border-b border-[var(--rule)] px-3 py-2 last:border-b-0"
						>
							<span class="u-mono w-48 shrink-0 truncate text-[12px]">{{ row.key }}</span>
							<span
								class="u-mono min-w-0 flex-1 break-all text-[12px]"
								:class="row.secret ? 'text-[var(--ink-ghost)]' : 'text-[var(--ink-soft)]'"
							>{{ format(row.value) }}</span>
							<span v-if="row.secret" class="u-chip shrink-0">hidden</span>
						</div>
						<p v-if="!config.data.values.length" class="u-item-detail px-3 py-4">
							{{ config.data.exists ? "This config is empty." : "No site_config.json here." }}
						</p>
					</div>

					<p class="u-mono text-[11px] text-[var(--ink-ghost)]">{{ config.data.path }}</p>
				</template>

				<div v-if="changed.length" class="u-note u-note-warn flex items-start gap-2.5">
					<Icon name="alert" :size="15" class="u-warn mt-0.5 shrink-0" />
					<p class="text-[12.5px] leading-relaxed">
						{{ changed.length }} unsaved
						{{ changed.length === 1 ? "change" : "changes" }}:
						<span class="u-mono">{{ changed.join(", ") }}</span>. A copy of the file is
						taken before anything is written.
					</p>
				</div>

				<p v-if="error" class="flex items-start gap-2 text-[12.5px] leading-relaxed">
					<Icon name="alert" :size="14" class="u-danger mt-[2px] shrink-0" />
					<span>{{ error }}</span>
				</p>
			</div>
		</template>

		<template #actions>
			<div class="flex justify-end gap-2">
				<Button @click="open = false">Close</Button>
				<Button variant="solid" :loading="saving" :disabled="!changed.length" @click="save">
					Save {{ changed.length || "" }}
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
import { siteConfigResource, updateSiteConfigResource } from "../api";

const TABS = ["Settings", "Everything"];

const props = defineProps({
	modelValue: { type: Boolean, default: false },
	bench: { type: String, required: true },
	sites: { type: Array, default: () => [] },
	defaultSite: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue"]);

const config = siteConfigResource();
const site = ref(null);
const view = ref("Settings");
/** Staged edits, keyed by setting. Only these are sent. */
const dirty = ref({});
const saving = ref(false);
const error = ref("");

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

const changed = computed(() => Object.keys(dirty.value));

/** Staged value if there is one, otherwise what is on disk. */
function current(setting) {
	return setting.key in dirty.value ? dirty.value[setting.key] : setting.effective;
}

function stage(setting, value) {
	const next = { ...dirty.value };
	// Setting it back to what it already is is not a change; drop it so the
	// save button reflects real work rather than every field that was touched.
	const same =
		setting.kind === "bool"
			? Boolean(value) === Boolean(setting.effective)
			: String(value ?? "") === String(setting.effective ?? "");
	if (same) delete next[setting.key];
	else next[setting.key] = value;
	dirty.value = next;
}

function format(value) {
	if (value === null || value === undefined) return "—";
	if (typeof value === "object") return JSON.stringify(value);
	return String(value);
}

function load() {
	if (!site.value?.value) return;
	dirty.value = {};
	error.value = "";
	config.fetch({ bench: props.bench, site: site.value.value });
}

async function save() {
	saving.value = true;
	error.value = "";
	try {
		const result = await updateSiteConfigResource().submit({
			bench: props.bench,
			site: site.value.value,
			changes: dirty.value,
		});
		dirty.value = {};
		config.data = result;
		toast.success(`Saved ${Object.keys(result.applied).length} change(s)`);
	} catch (err) {
		error.value = err.messages?.[0] || err.message || "Could not save the change";
	} finally {
		saving.value = false;
	}
}

watch(
	() => props.modelValue,
	(isOpen) => {
		if (!isOpen) {
			dirty.value = {};
			return;
		}
		if (!site.value) {
			const preferred = props.defaultSite || props.sites[0];
			if (preferred) site.value = { label: preferred, value: preferred };
		}
		load();
	},
);

watch(site, load);
</script>
