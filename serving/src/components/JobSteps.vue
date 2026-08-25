<template>
	<div class="flex flex-col gap-1">
		<div v-for="step in steps" :key="step.key" class="overflow-hidden rounded-md border" :class="borderFor(step)">
			<button
				type="button"
				class="flex w-full items-center gap-2.5 px-2.5 py-2 text-left transition-colors duration-150"
				:class="step.status === 'Pending' ? 'opacity-55' : 'hover:bg-[var(--paper-sunk)]'"
				@click="toggle(step)"
			>
				<!--
					One glyph per state, never colour alone. This interface is
					monochrome apart from the semantic accents, and "failed" is
					exactly the thing that has to survive being printed, screenshotted
					or read by someone who cannot separate red from green.
				-->
				<span class="grid h-4 w-4 shrink-0 place-items-center">
					<Spinner v-if="step.status === 'Running'" class="h-3.5 w-3.5 u-live" />
					<Icon v-else-if="step.status === 'Success'" name="check" :size="13" class="u-ok" />
					<Icon v-else-if="step.status === 'Failure'" name="close" :size="13" class="u-danger" />
					<Icon
						v-else-if="step.status === 'Skipped'"
						name="chevron"
						:size="12"
						class="text-[var(--ink-ghost)]"
					/>
					<span v-else class="h-1.5 w-1.5 rounded-full bg-[var(--ink-ghost)]" />
				</span>

				<span class="min-w-0 flex-1">
					<span class="u-item-label block truncate">{{ step.title }}</span>
					<span class="u-item-detail block truncate">
						{{ step.detail || step.description }}
					</span>
				</span>

				<span v-if="step.duration != null" class="u-item-detail shrink-0 tabular-nums">
					{{ formatDuration(step.duration) }}
				</span>
				<Icon
					v-if="step.output"
					name="chevron"
					:size="12"
					class="shrink-0 text-[var(--ink-ghost)] transition-transform duration-200"
					:class="isOpen(step) ? 'rotate-90' : ''"
				/>
			</button>

			<!-- A running step is open whether or not you asked, because the
			     whole reason to watch is to see it moving. -->
			<div v-if="step.output && isOpen(step)" class="border-t border-[var(--rule)]">
				<pre
					ref="panes"
					class="u-scroll u-mono max-h-[220px] overflow-auto whitespace-pre-wrap break-all bg-[var(--paper-sunk)] px-2.5 py-2 text-[11px] leading-relaxed text-[var(--ink-soft)]"
				>{{ step.output }}</pre>
			</div>
		</div>

		<p v-if="!steps.length" class="u-item-detail px-1 py-2">
			No steps recorded — this ran before steps existed. The full output is below.
		</p>
	</div>
</template>

<script setup>
import { computed, nextTick, ref, watch } from "vue";
import { Spinner } from "frappe-ui";
import Icon from "./Icon.vue";

const props = defineProps({
	steps: { type: Array, default: () => [] },
});

/** Steps the user has explicitly toggled, keyed by step. */
const overrides = ref({});

function isOpen(step) {
	if (step.key in overrides.value) return overrides.value[step.key];
	// Open by default while running, and when it failed — those are the two
	// moments the output is the thing you came for.
	return step.status === "Running" || step.status === "Failure";
}

function toggle(step) {
	if (!step.output) return;
	overrides.value = { ...overrides.value, [step.key]: !isOpen(step) };
}

function formatDuration(seconds) {
	if (seconds < 1) return "<1s";
	if (seconds < 60) return `${Math.round(seconds)}s`;
	const mins = Math.floor(seconds / 60);
	return `${mins}m ${Math.round(seconds % 60)}s`;
}

function borderFor(step) {
	if (step.status === "Failure") return "border-[var(--danger-border)]";
	if (step.status === "Running") return "border-[var(--live)]";
	return "border-[var(--rule)]";
}

// Follow the tail of whatever is running, the way a terminal does.
const panes = ref([]);
const runningOutput = computed(() => props.steps.find((s) => s.status === "Running")?.output);
watch(runningOutput, () => {
	nextTick(() => {
		for (const pane of panes.value || []) pane.scrollTop = pane.scrollHeight;
	});
});
</script>
