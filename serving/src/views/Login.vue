<template>
	<div class="grid min-h-full place-items-center bg-[var(--paper)] px-5 py-10">
		<div class="u-enter w-full max-w-[336px]">
			<div class="mb-7 flex items-center gap-2.5">
				<span class="grid h-8 w-8 place-items-center rounded-lg bg-[var(--ink)] text-[var(--paper)]">
					<Icon name="shield" :size="17" stroke-width="2" />
				</span>
				<div>
					<p class="u-display text-[15px] leading-tight">Server</p>
					<p class="text-[11.5px] leading-tight text-[var(--ink-faint)]">SSH access &amp; bench control</p>
				</div>
			</div>

			<form class="flex flex-col gap-3" @submit.prevent="submit">
				<label class="flex flex-col gap-1.5">
					<span class="u-label">Email</span>
					<input
						v-model="email"
						type="text"
						autocomplete="username"
						required
						class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-3 py-2 text-[13.5px] outline-none transition-colors focus:border-[var(--ink)]"
					/>
				</label>

				<label class="flex flex-col gap-1.5">
					<span class="u-label">Password</span>
					<input
						v-model="password"
						type="password"
						autocomplete="current-password"
						required
						class="rounded-md border border-[var(--rule)] bg-[var(--paper)] px-3 py-2 text-[13.5px] outline-none transition-colors focus:border-[var(--ink)]"
					/>
				</label>

				<Transition
					enter-active-class="transition-all duration-200 ease-[var(--ease)]"
					enter-from-class="opacity-0 -translate-y-1"
				>
					<p v-if="error" class="flex items-start gap-1.5 text-[12.5px] leading-relaxed text-[var(--ink)]">
						<Icon name="alert" :size="14" class="mt-[1px] shrink-0" />
						<span>{{ error }}</span>
					</p>
				</Transition>

				<button
					type="submit"
					class="mt-1 flex items-center justify-center gap-2 rounded-md bg-[var(--ink)] px-3 py-2 text-[13.5px] font-medium text-[var(--paper)] transition-opacity duration-150 hover:opacity-88 disabled:cursor-not-allowed disabled:opacity-45"
					:disabled="busy"
				>
					<Spinner v-if="busy" class="h-3.5 w-3.5" />
					{{ busy ? "Signing in…" : "Sign in" }}
				</button>
			</form>
		</div>
	</div>
</template>

<script setup>
import { inject, ref } from "vue";
import { Spinner, toast } from "frappe-ui";
import { useRoute, useRouter } from "vue-router";
import Icon from "../components/Icon.vue";

const $auth = inject("$auth");
const router = useRouter();
const route = useRoute();

const email = ref("");
const password = ref("");
const busy = ref(false);
const error = ref("");

async function submit() {
	if (!email.value || !password.value) return;
	busy.value = true;
	error.value = "";
	try {
		const result = await $auth.login(email.value, password.value);
		if (result) {
			toast.success("Signed in");
			// Honour the route the guard bounced us away from, if there was one.
			const target = route.query.route;
			router.push(typeof target === "string" && target ? target : { name: "Dashboard" });
		} else {
			error.value = "Those credentials were not accepted.";
		}
	} catch (err) {
		error.value = err?.messages?.[0] || err?.message || "Could not sign in.";
	} finally {
		busy.value = false;
	}
}
</script>
