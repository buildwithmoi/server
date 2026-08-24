<!--
  Loading placeholder.

  Shaped like the content it stands in for, rather than a generic spinner: a
  block the size of the real row means the layout does not jump when data
  lands, which is the whole point of a skeleton over a spinner.
-->
<template>
	<div class="u-skeleton" :style="{ height, width, borderRadius: radius }" role="presentation" />
</template>

<script setup>
defineProps({
	height: { type: String, default: "1rem" },
	width: { type: String, default: "100%" },
	radius: { type: String, default: "6px" },
});
</script>
