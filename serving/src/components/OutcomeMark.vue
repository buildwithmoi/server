<!--
  Severity indicator.

  Encoded by FILL and LABEL, never by hue: filled square = failure, hollow =
  success, small dash = informational. In a greyscale interface a coloured dot
  would be indistinguishable, and even in a coloured one roughly one man in
  twelve cannot separate red from green.
-->
<template>
	<span class="inline-flex items-center gap-1.5 whitespace-nowrap">
		<svg width="8" height="8" viewBox="0 0 8 8" aria-hidden="true" class="shrink-0">
			<rect
				v-if="outcome === 'Failure'"
				x="0.5" y="0.5" width="7" height="7"
				fill="currentColor" stroke="currentColor"
			/>
			<rect
				v-else-if="outcome === 'Success'"
				x="0.75" y="0.75" width="6.5" height="6.5"
				fill="none" stroke="currentColor" stroke-width="1.5"
			/>
			<rect v-else x="0" y="3.25" width="8" height="1.5" fill="currentColor" opacity="0.5" />
		</svg>
		<span v-if="withLabel" :class="outcome === 'Failure' ? 'font-medium' : ''">{{ label }}</span>
	</span>
</template>

<script setup>
import { computed } from "vue";

const props = defineProps({
	outcome: { type: String, default: "Info" },
	label: { type: String, default: "" },
	withLabel: { type: Boolean, default: true },
});

const label = computed(() => props.label || props.outcome);
</script>
