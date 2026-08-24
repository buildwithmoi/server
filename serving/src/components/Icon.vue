<!--
  A tiny inline icon set.

  Deliberately hand-rolled rather than pulling an icon package: this app needs
  eight glyphs, every one is a stroke path that inherits currentColor, and that
  keeps them correct in a monochrome theme without a build-time icon resolver in
  the dependency graph.
-->
<template>
	<svg
		:width="size"
		:height="size"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		:stroke-width="strokeWidth"
		stroke-linecap="round"
		stroke-linejoin="round"
		aria-hidden="true"
		focusable="false"
	>
		<path v-for="(d, i) in paths" :key="i" :d="d" />
		<circle v-for="(c, i) in circles" :key="`c${i}`" :cx="c[0]" :cy="c[1]" :r="c[2]" />
	</svg>
</template>

<script setup>
import { computed } from "vue";

const props = defineProps({
	name: { type: String, required: true },
	size: { type: [Number, String], default: 18 },
	strokeWidth: { type: [Number, String], default: 1.6 },
});

const SHAPES = {
	gauge: { paths: ["M12 14 16 9", "M4.5 19a9 9 0 1 1 15 0"], circles: [[12, 14, 1.4]] },
	shield: { paths: ["M12 3 20 6.5v5c0 5-3.4 8.3-8 9.5-4.6-1.2-8-4.5-8-9.5v-5L12 3Z"] },
	terminal: { paths: ["M5 8l4 4-4 4", "M13 16h6"] },
	globe: { paths: ["M2.6 9h18.8", "M2.6 15h18.8", "M12 3a15 15 0 0 1 0 18", "M12 3a15 15 0 0 0 0 18"], circles: [[12, 12, 9]] },
	sliders: { paths: ["M4 7h10", "M18 7h2", "M4 17h4", "M12 17h8"], circles: [[16, 7, 2], [10, 17, 2]] },
	logout: { paths: ["M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4", "M10 8 6 12l4 4", "M6 12h11"] },
	refresh: { paths: ["M20 12a8 8 0 1 1-2.6-5.9", "M20 4v5h-5"] },
	alert: { paths: ["M12 8.5v4.5", "M10.3 3.6 2.6 17a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0Z"], circles: [[12, 16.6, 0.6]] },
	check: { paths: ["M5 12.5 10 17.5 19 7"] },
	search: { paths: ["M20 20l-3.4-3.4"], circles: [[11, 11, 7]] },
	chevron: { paths: ["M9 6l6 6-6 6"] },
	play: { paths: ["M7 4.8v14.4L19 12 7 4.8Z"] },
	trash: { paths: ["M4 7h16", "M9 7V5h6v2", "M6 7l1 13h10l1-13"] },
	layers: { paths: ["M12 3 3 7.5l9 4.5 9-4.5L12 3Z", "M3 12.5 12 17l9-4.5", "M3 17.5 12 22l9-4.5"] },
	download: { paths: ["M12 3v11", "M7.5 10 12 14.5 16.5 10", "M4 20h16"] },
	key: { paths: ["M14.5 10.5 21 4", "M18 7l2 2", "M16 9l1.5 1.5"], circles: [[8.5, 15.5, 5]] },
};

const shape = computed(() => SHAPES[props.name] || SHAPES.gauge);
const paths = computed(() => shape.value.paths || []);
const circles = computed(() => shape.value.circles || []);
</script>
