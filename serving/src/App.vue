<template>
	<RouterView v-slot="{ Component }">
		<Transition name="page" mode="out-in">
			<component :is="Component" />
		</Transition>
	</RouterView>
	<Toast />
</template>

<script setup>
import { Toast } from "frappe-ui";
</script>
