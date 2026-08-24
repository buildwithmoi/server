<!--
  A ranked list with the magnitude drawn behind the label.

  Preferred over a pie or donut for "top countries" and "top attackers":
  comparing bar lengths is far more accurate than comparing arc angles, and the
  label stays readable at any count.
-->
<template>
	<ul class="flex flex-col">
		<li
			v-for="(row, i) in rows"
			:key="row.key"
			class="group relative flex items-center justify-between gap-3 border-b border-[var(--rule)] px-3 py-2 last:border-0"
		>
			<!-- magnitude, drawn as a wash behind the text -->
			<span
				class="pointer-events-none absolute inset-y-0 left-0 bg-[var(--ink)] opacity-[0.055] transition-all duration-500"
				:style="{ width: `${row.pct}%` }"
				aria-hidden="true"
			/>
			<span class="relative flex min-w-0 items-center gap-2.5">
				<span class="u-num w-4 shrink-0 text-[11px] text-[var(--ink-ghost)]">{{ i + 1 }}</span>
				<span class="truncate text-[13px]" :class="mono ? 'u-mono' : ''">{{ row.label }}</span>
				<span v-if="row.note" class="truncate text-[11px] text-[var(--ink-faint)]">{{ row.note }}</span>
			</span>
			<span class="u-num relative shrink-0 text-[13px] font-medium">{{ row.value.toLocaleString() }}</span>
		</li>
	</ul>
</template>

<script setup>
import { computed } from "vue";

const props = defineProps({
	items: { type: Array, default: () => [] },
	labelKey: { type: String, default: "label" },
	valueKey: { type: String, default: "value" },
	noteKey: { type: String, default: "" },
	mono: { type: Boolean, default: false },
});

const rows = computed(() => {
	const max = Math.max(1, ...props.items.map((i) => Number(i[props.valueKey]) || 0));
	return props.items.map((item, index) => ({
		key: `${item[props.labelKey]}-${index}`,
		label: item[props.labelKey] ?? "—",
		value: Number(item[props.valueKey]) || 0,
		note: props.noteKey ? item[props.noteKey] : "",
		pct: ((Number(item[props.valueKey]) || 0) / max) * 100,
	}));
});
</script>
