<template>
	<Dialog v-model="open" :options="{ title: `Logs · ${bench}`, size: '4xl' }">
		<template #body-content>
			<div class="flex flex-col gap-3">
				<div class="flex flex-col gap-1.5">
					<span class="u-label">Log file</span>
					<SearchSelect
						v-model="picked"
						:options="options"
						placeholder="Choose a log"
						search-placeholder="Search by name or what it holds"
						empty-text="This bench has no log files."
						:loading="listing.loading"
						mono
					/>
				</div>

				<div v-if="picked" class="flex flex-wrap items-center gap-2">
					<div class="relative min-w-[200px] flex-1">
						<Icon
							name="search"
							:size="13"
							class="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--ink-ghost)]"
						/>
						<input
							v-model.trim="search"
							type="text"
							placeholder="Filter lines — case-insensitive"
							class="w-full rounded-md border border-[var(--rule)] bg-[var(--paper)] py-1.5 pl-7 pr-2 text-[13px] outline-none focus:border-[var(--ink)]"
							@keydown.enter.prevent.stop="load"
						/>
					</div>

					<select
						v-model.number="lines"
						class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-2 py-1.5 text-[13px] outline-none focus:border-[var(--ink)]"
						@change="load"
					>
						<option v-for="n in [100, 300, 1000, 5000]" :key="n" :value="n">
							last {{ n.toLocaleString() }}
						</option>
					</select>

					<Button :loading="reader.loading" @click="load">
						<template #prefix><Icon name="refresh" :size="13" /></template>
						Refresh
					</Button>

					<!-- Following re-reads the tail on a timer. Only offered while a
					     file is open, and stopped when the dialog closes — a poller
					     left running behind a closed dialog is a bug you find weeks
					     later as mystery load. -->
					<label class="flex cursor-pointer items-center gap-1.5">
						<input v-model="follow" type="checkbox" />
						<span class="u-item-detail">Follow</span>
					</label>
				</div>

				<div v-if="result?.error" class="u-note u-note-danger flex items-start gap-2.5">
					<Icon name="alert" :size="15" class="u-danger mt-0.5 shrink-0" />
					<p class="text-[12.5px] leading-relaxed">{{ result.error }}</p>
				</div>

				<template v-else-if="picked">
					<p class="u-item-detail">
						<template v-if="result?.matched != null">
							{{ result.matched.toLocaleString() }} matching
							{{ result.matched === 1 ? "line" : "lines" }} in
							{{ result.scanned?.toLocaleString() }} scanned<template v-if="result.truncated">
								— showing the last {{ lines.toLocaleString() }}</template>.
						</template>
						<template v-else>
							{{ selected?.size_text }} · written {{ selected?.modified_text }}<template
								v-if="result?.truncated"
							>
								· showing the last {{ lines.toLocaleString() }} lines</template>.
						</template>
					</p>

					<pre
						ref="pane"
						class="u-scroll u-mono max-h-[52vh] min-h-[220px] overflow-auto whitespace-pre-wrap break-all rounded-md border border-[var(--rule)] bg-[var(--paper-sunk)] px-3 py-2.5 text-[11.5px] leading-relaxed"
					>{{ body }}</pre>
				</template>
			</div>
		</template>

		<template #actions>
			<div class="flex items-center justify-between gap-2">
				<span v-if="picked" class="u-mono truncate text-[11px] text-[var(--ink-ghost)]">
					{{ picked.value }}
				</span>
				<div class="flex shrink-0 gap-2">
					<Button v-if="body" @click="copy">Copy</Button>
					<Button variant="solid" @click="open = false">Close</Button>
				</div>
			</div>
		</template>
	</Dialog>
</template>

<script setup>
import { computed, nextTick, onUnmounted, ref, watch } from "vue";
import { Button, Dialog, toast } from "frappe-ui";
import Icon from "./Icon.vue";
import SearchSelect from "./SearchSelect.vue";
import { logsResource, readLogResource } from "../api";

const FOLLOW_MS = 4000;

const props = defineProps({
	modelValue: { type: Boolean, default: false },
	bench: { type: String, required: true },
});
const emit = defineEmits(["update:modelValue"]);

const listing = logsResource();
const reader = readLogResource();
const picked = ref(null);
const search = ref("");
const lines = ref(300);
const follow = ref(false);
const pane = ref(null);
let timer = null;

const open = computed({
	get: () => props.modelValue,
	set: (v) => emit("update:modelValue", v),
});

const files = computed(() => listing.data?.files || []);
const selected = computed(() => files.value.find((f) => f.path === picked.value?.value) || null);
const result = computed(() => reader.data || null);
const body = computed(() =>
	result.value?.lines?.length
		? result.value.lines.join("\n")
		: result.value
			? search.value
				? `Nothing in this file matches “${search.value}”.`
				: "This log is empty."
			: "",
);

const options = computed(() =>
	files.value.map((f) => ({
		label: f.name,
		value: f.path,
		description: [f.description, f.is_rotation ? "Rotated — an older slice of the same log." : ""]
			.filter(Boolean)
			.join(" "),
		chip: f.scope === "bench" ? f.size_text : f.scope,
		chipClass: "u-chip",
		keywords: `${f.scope} ${f.path}`,
	})),
);

function load() {
	if (!picked.value?.value) return;
	reader.fetch({
		bench: props.bench,
		path: picked.value.value,
		lines: lines.value,
		search: search.value || null,
	});
}

async function copy() {
	try {
		await navigator.clipboard.writeText(body.value);
		toast.success("Copied");
	} catch {
		toast.error("Could not copy");
	}
}

watch(
	() => props.modelValue,
	(isOpen) => {
		if (isOpen) {
			listing.fetch({ bench: props.bench });
		} else {
			// Never leave a poller running behind a closed dialog.
			follow.value = false;
		}
	},
);

watch(picked, () => {
	search.value = "";
	load();
});

watch([follow, () => props.modelValue], ([on, isOpen]) => {
	if (timer) clearInterval(timer);
	timer = null;
	if (on && isOpen) timer = setInterval(load, FOLLOW_MS);
});

// Stay pinned to the bottom, the way `tail -f` does — but only when already
// there, so following does not yank the view away from something being read.
watch(body, () => {
	const el = pane.value;
	if (!el) return;
	const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
	if (atBottom || !follow.value) nextTick(() => (el.scrollTop = el.scrollHeight));
});

onUnmounted(() => timer && clearInterval(timer));
</script>
