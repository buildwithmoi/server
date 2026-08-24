<template>
	<div class="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
		<Icon :name="icon" :size="26" class="text-[var(--ink-ghost)]" />
		<p class="text-sm font-medium text-[var(--ink)]">{{ title }}</p>
		<p v-if="hint" class="max-w-sm text-[13px] leading-relaxed text-[var(--ink-faint)]">{{ hint }}</p>
		<slot />
	</div>
</template>

<script setup>
import Icon from "./Icon.vue";

defineProps({
	title: { type: String, required: true },
	hint: { type: String, default: "" },
	icon: { type: String, default: "search" },
});
</script>
