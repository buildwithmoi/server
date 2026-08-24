<!--
  Daily failure/success bars, drawn as inline SVG.

  Hand-drawn rather than charted with a library: the whole shape is two stacked
  rectangles per day, and pulling in a charting engine for that would add
  hundreds of kilobytes and a theming layer to fight. Inline SVG also inherits
  currentColor, so it is monochrome for free.

  Failures are solid; successes are a hatched fill. Both are visible in
  greyscale and distinguishable without relying on lightness alone.
-->
<template>
	<div>
		<svg :viewBox="`0 0 ${width} ${height}`" class="w-full" :style="{ height: `${height}px` }" role="img"
		     :aria-label="`Daily activity over ${points.length} days`">
			<defs>
				<pattern id="hatch" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
					<rect width="4" height="4" fill="var(--paper)" />
					<line x1="0" y1="0" x2="0" y2="4" stroke="var(--ink)" stroke-width="2" opacity="0.42" />
				</pattern>
			</defs>

			<!-- baseline -->
			<line :x1="0" :y1="plotH" :x2="width" :y2="plotH" stroke="var(--rule-strong)" stroke-width="1" />

			<g v-for="(p, i) in scaled" :key="p.day">
				<rect
					:x="p.x" :y="plotH - p.successH - p.failureH"
					:width="barW" :height="p.failureH"
					fill="var(--ink)"
				>
					<title>{{ p.day }} — {{ p.failure }} failed</title>
				</rect>
				<rect
					:x="p.x" :y="plotH - p.successH"
					:width="barW" :height="p.successH"
					fill="url(#hatch)" stroke="var(--ink)" stroke-width="0.75"
				>
					<title>{{ p.day }} — {{ p.success }} succeeded</title>
				</rect>
				<text
					v-if="i % labelEvery === 0"
					:x="p.x + barW / 2" :y="height - 3"
					text-anchor="middle" font-size="9.5" fill="var(--ink-faint)"
				>{{ shortDay(p.day) }}</text>
			</g>
		</svg>

		<div class="mt-2 flex items-center gap-4 text-[11px] text-[var(--ink-faint)]">
			<span class="inline-flex items-center gap-1.5">
				<svg width="9" height="9"><rect width="9" height="9" fill="var(--ink)" /></svg> Failed
			</span>
			<span class="inline-flex items-center gap-1.5">
				<svg width="9" height="9"><rect width="9" height="9" fill="url(#hatch)" stroke="var(--ink)" stroke-width="0.75" /></svg>
				Succeeded
			</span>
		</div>
	</div>
</template>

<script setup>
import { computed } from "vue";

const props = defineProps({
	points: { type: Array, default: () => [] },
	height: { type: Number, default: 132 },
});

const width = 600;
const plotH = computed(() => props.height - 16);
const gap = 5;

const barW = computed(() => {
	const n = Math.max(props.points.length, 1);
	return Math.max((width - gap * (n - 1)) / n, 2);
});

const labelEvery = computed(() => (props.points.length > 14 ? Math.ceil(props.points.length / 7) : 1));

const scaled = computed(() => {
	const max = Math.max(1, ...props.points.map((p) => (p.failure || 0) + (p.success || 0)));
	return props.points.map((p, i) => {
		const total = plotH.value - 6;
		return {
			...p,
			x: i * (barW.value + gap),
			failureH: ((p.failure || 0) / max) * total,
			successH: ((p.success || 0) / max) * total,
		};
	});
});

function shortDay(day) {
	const d = new Date(day);
	return Number.isNaN(d.getTime()) ? day : `${d.getDate()}/${d.getMonth() + 1}`;
}
</script>
