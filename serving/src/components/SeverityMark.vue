<template>
	<span class="inline-flex items-center gap-1.5 whitespace-nowrap">
		<!--
			A filled dot rather than a coloured pill. Four severities on one
			screen, each in its own block of colour, reads as a warning label
			on every row and stops meaning anything — the dot carries the
			signal and the text carries the weight.
		-->
		<span class="h-[7px] w-[7px] shrink-0 rounded-full" :class="dotClass" />
		<!--
			An explicitly empty `label` means the dot alone, for places where the
			severity word is already on screen beside it. Falling back to the
			severity here instead printed it twice — "Critical 13 Critical".
		-->
		<span v-if="text" class="text-[13px]" :class="textClass">{{ text }}</span>
	</span>
</template>

<script setup>
import { computed } from "vue";

const props = defineProps({
	severity: { type: String, default: "Info" },
	/** Pass "" for the dot on its own; omit it entirely to show the severity. */
	label: { type: String, default: undefined },
});

const text = computed(() => (props.label === undefined ? props.severity : props.label));

/**
 * Colour is never the only carrier: the word is always present. Roughly one in
 * twelve men cannot separate the red from the amber, and this is a screen
 * somebody reads when something has gone wrong.
 */
const DOTS = {
	Critical: "bg-[var(--danger)]",
	High: "bg-[var(--warn)]",
	Medium: "bg-[var(--warn-border)]",
	Info: "bg-[var(--ink-ghost)]",
};
const TEXT = {
	Critical: "font-medium text-[var(--danger)]",
	High: "font-medium text-[var(--warn)]",
	Medium: "text-[var(--ink)]",
	Info: "text-[var(--ink-faint)]",
};

const dotClass = computed(() => DOTS[props.severity] || DOTS.Info);
const textClass = computed(() => TEXT[props.severity] || TEXT.Info);
</script>
