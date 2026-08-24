<!--
  A headline number.

  The value counts up on mount. That is not decoration: a number that animates
  from zero tells you it was just refreshed, which matters on a page you leave
  open and glance at.
-->
<template>
	<div class="u-card px-4 py-3.5 transition-shadow duration-200 hover:shadow-[0_1px_0_var(--rule-strong)]">
		<div class="flex items-start justify-between gap-3">
			<p class="u-label">{{ label }}</p>
			<slot name="badge" />
		</div>

		<div class="mt-2 flex items-baseline gap-2">
			<Skeleton v-if="loading" height="1.9rem" width="3.5rem" />
			<template v-else>
				<span class="u-display u-num text-[27px] leading-none">{{ display }}</span>
				<span v-if="suffix" class="text-[13px] text-[var(--ink-faint)]">{{ suffix }}</span>
			</template>
		</div>

		<p v-if="hint && !loading" class="mt-1.5 text-[12px] leading-snug text-[var(--ink-faint)]">
			{{ hint }}
		</p>
	</div>
</template>

<script setup>
import { onMounted, ref, watch } from "vue";
import Skeleton from "./Skeleton.vue";

const props = defineProps({
	label: { type: String, required: true },
	value: { type: [Number, String], default: 0 },
	suffix: { type: String, default: "" },
	hint: { type: String, default: "" },
	loading: { type: Boolean, default: false },
});

const display = ref(0);

/**
 * Count up to the target over ~450ms.
 *
 * Bails out for non-numeric values, and honours prefers-reduced-motion by
 * jumping straight to the final figure.
 */
function animateTo(target) {
	const end = Number(target);
	if (!Number.isFinite(end)) {
		display.value = target;
		return;
	}
	if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
		display.value = end.toLocaleString();
		return;
	}

	const duration = 450;
	const start = performance.now();
	const from = 0;

	function step(now) {
		const t = Math.min((now - start) / duration, 1);
		// easeOutCubic — fast first, settles gently on the real number.
		const eased = 1 - Math.pow(1 - t, 3);
		display.value = Math.round(from + (end - from) * eased).toLocaleString();
		if (t < 1) requestAnimationFrame(step);
	}
	requestAnimationFrame(step);
}

onMounted(() => !props.loading && animateTo(props.value));
watch(
	() => [props.value, props.loading],
	([value, loading]) => !loading && animateTo(value),
);
</script>
