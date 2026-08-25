<template>
	<Dialog
		v-model="open"
		:options="{ title: `Bench commands · ${bench}`, size: 'xl' }"
		:disable-outside-click-to-close="busy"
	>
		<template #body-content>
			<div class="flex flex-col gap-3.5">
				<div class="flex flex-col gap-1.5">
					<span class="u-label">Command</span>
					<SearchSelect
						v-model="picked"
						:options="options"
						placeholder="Choose a command"
						search-placeholder="Search by name or what it does"
						empty-text="No command matches that."
						:loading="resource.loading"
					/>
					<p class="text-[11.5px] leading-relaxed text-[var(--ink-faint)]">
						{{ runnableCount }} runnable, {{ unsupportedCount }} listed but not runnable from
						here. Search matches the name and what it does.
					</p>
				</div>

				<template v-if="command">
					<!-- What it is, and exactly what will run. -->
					<div class="rounded-md border border-[var(--rule)] bg-[var(--paper-sunk)] px-3 py-2.5">
						<div class="flex items-start justify-between gap-3">
							<p class="text-[13px] font-medium">{{ command.label }}</p>
							<RiskTag :risk="command.risk" />
						</div>
						<p class="mt-1 text-[12.5px] leading-relaxed text-[var(--ink-soft)]">
							{{ command.description }}
						</p>
						<p class="u-mono mt-2 break-all text-[11.5px] text-[var(--ink-faint)]">
							$ {{ resolvedPreview }}
						</p>
					</div>

					<!-- Not runnable: say why, rather than hiding it from search. -->
					<div
						v-if="!command.runnable"
						class="u-note u-note-warn flex items-start gap-2.5"
					>
						<Icon name="alert" :size="15" class="u-warn mt-0.5 shrink-0" />
						<p class="text-[12.5px] leading-relaxed">{{ command.unsupported_reason }}</p>
					</div>

					<template v-else>
						<label v-if="command.scope === 'site'" class="flex flex-col gap-1.5">
							<span class="u-label">Site</span>
							<select
								v-model="site"
								class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
							>
								<option value="" disabled>choose a site</option>
								<option v-for="s in sites" :key="s" :value="s">{{ s }}</option>
							</select>
						</label>

						<label
							v-for="param in command.params"
							:key="param.name"
							class="flex flex-col gap-1.5"
						>
							<span class="u-label">{{ param.label }}</span>
							<input
								v-model.trim="params[param.name]"
								:placeholder="param.placeholder"
								class="u-mono rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
							/>
						</label>

						<!-- Destructive needs the name typed out. A checkbox is
						     something you tick without reading; typing "Drop site"
						     is not something you do by reflex. -->
						<div
							v-if="command.risk === 'destructive'"
							class="u-note u-note-danger flex flex-col gap-2"
						>
							<div class="flex items-start gap-2.5">
								<Icon name="alert" :size="15" class="u-danger mt-0.5 shrink-0" />
								<p class="text-[12.5px] leading-relaxed">
									This can lose data, and nothing here takes a backup first. Type
									<span class="font-medium">{{ command.label }}</span> to confirm.
								</p>
							</div>
							<input
								v-model.trim="confirm"
								:placeholder="command.label"
								class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2.5 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
							/>
						</div>
					</template>
				</template>

				<p v-if="error" class="flex items-start gap-2 text-[12.5px] leading-relaxed">
					<Icon name="alert" :size="14" class="mt-[2px] shrink-0" />
					<span>{{ error }}</span>
				</p>
			</div>
		</template>

		<template #actions>
			<div class="flex justify-end gap-2">
				<Button @click="open = false">Cancel</Button>
				<Button variant="solid" :loading="running" :disabled="!canRun" @click="run">Run</Button>
			</div>
		</template>
	</Dialog>
</template>

<script setup>
import { computed, h, ref, watch } from "vue";
import { Button, Dialog, toast } from "frappe-ui";
import Icon from "./Icon.vue";
import SearchSelect from "./SearchSelect.vue";
import { watchJob } from "../jobs";
import { useBusyGuard } from "../busy";
import { benchCommandsResource, runBenchCommandResource } from "../api";

const props = defineProps({
	modelValue: { type: Boolean, default: false },
	bench: { type: String, required: true },
	sites: { type: Array, default: () => [] },
	defaultSite: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue", "started"]);

/**
 * Risk shown as a word inside a bordered tag, never as a colour.
 *
 * The interface is monochrome apart from the running-job beacon, and
 * "destructive" is exactly the sort of thing that must survive greyscale.
 */
const RiskTag = (p) =>
	h(
		"span",
		{ class: `u-chip shrink-0 ${CHIP[p.risk] || "u-chip"}` },
		p.risk === "unsupported" ? "not runnable" : p.risk,
	);
RiskTag.props = ["risk"];

const resource = benchCommandsResource();
const picked = ref(null);
const site = ref("");
const params = ref({});
const confirm = ref("");
const running = ref(false);
const error = ref("");

// Closing mid-flight loses the work — the dialog owns it, and there is no
// job card to come back to. See busy.ts.
const busy = computed(() => running.value);
useBusyGuard(busy);

const open = computed({
	get: () => props.modelValue,
	set: (v) => emit("update:modelValue", v),
});

const catalogue = computed(() => resource.data || []);
const runnableCount = computed(() => catalogue.value.filter((c) => c.runnable).length);
const unsupportedCount = computed(() => catalogue.value.length - runnableCount.value);
const command = computed(() => catalogue.value.find((c) => c.id === picked.value?.value) || null);

const CHIP = {
	read: "u-chip",
	routine: "u-chip",
	destructive: "u-chip-danger",
	unsupported: "u-chip-warn",
};

const options = computed(() =>
	catalogue.value.map((c) => ({
		label: c.label,
		value: c.id,
		description: c.description,
		// Risk belongs in a chip, not buried in the middle of the sentence that
		// explains what the command does.
		chip: c.runnable ? c.risk : "n/a",
		chipClass: CHIP[c.risk] || "u-chip",
		// Searched but not shown, so `bench migrate` finds Migrate.
		keywords: `${c.scope} ${c.preview} ${c.risk}`,
	})),
);

const resolvedPreview = computed(() =>
	(command.value?.preview || "").replace("<site>", site.value || "<site>"),
);

const canRun = computed(() => {
	const c = command.value;
	if (!c || !c.runnable) return false;
	if (c.scope === "site" && !site.value) return false;
	if (c.params.some((p) => p.required && !(params.value[p.name] || "").trim())) return false;
	if (c.risk === "destructive" && confirm.value !== c.label) return false;
	return true;
});

watch(
	() => props.modelValue,
	(isOpen) => {
		if (!isOpen) return;
		error.value = "";
		resource.fetch();
		if (!site.value) site.value = props.defaultSite || props.sites[0] || "";
	},
);

watch(command, () => {
	params.value = {};
	confirm.value = "";
	error.value = "";
});

async function run() {
	running.value = true;
	error.value = "";
	try {
		const result = await runBenchCommandResource().submit({
			bench: props.bench,
			command: command.value.id,
			site: command.value.scope === "site" ? site.value : null,
			params: params.value,
			confirm: confirm.value || null,
		});
		watchJob(result.name, {
			operation: "Command",
			app_name: command.value.label,
			bench: props.bench,
			status: "Queued",
		});
		toast.success(`${command.value.label} started`);
		open.value = false;
		emit("started", result.name);
	} catch (err) {
		error.value = err.messages?.[0] || err.message || "Could not start the command";
	} finally {
		running.value = false;
	}
}
</script>
