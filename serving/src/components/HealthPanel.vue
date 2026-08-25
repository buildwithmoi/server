<template>
	<section v-if="data" class="u-card mb-5 overflow-hidden">
		<header class="flex items-center justify-between gap-3 border-b border-[var(--rule)] px-4 py-2.5">
			<div class="flex min-w-0 items-center gap-2">
				<Icon name="gauge" :size="15" class="shrink-0 text-[var(--ink-faint)]" />
				<span class="u-item-label truncate">{{ data.hostname }}</span>
				<span v-if="data.uptime" class="u-item-detail shrink-0">up {{ data.uptime.text }}</span>
			</div>
			<span v-if="data.worst_level !== 'ok'" class="u-chip shrink-0" :class="chipFor(data.worst_level)">
				needs attention
			</span>
		</header>

		<div class="grid gap-px bg-[var(--rule)] sm:grid-cols-2 lg:grid-cols-4">
			<Gauge
				v-for="gauge in gauges"
				:key="gauge.label"
				v-bind="gauge"
			/>
		</div>

		<!--
			Only shown when the disk is actually under pressure. Backups are what
			fills a bench host — they accumulate on a schedule, nothing prunes
			them, and no other screen would ever tell you which site is
			responsible. Showing it permanently would be noise; showing it at 80%
			is the answer to the question you just started asking.
		-->
		<div v-if="data.backups?.length" class="border-t border-[var(--rule)] px-4 py-3">
			<p class="u-item-detail mb-2">
				Backups are usually what fills a bench host. Largest first:
			</p>
			<ul class="flex flex-col gap-1">
				<li
					v-for="row in data.backups.slice(0, 5)"
					:key="row.path"
					class="flex items-baseline justify-between gap-3"
				>
					<span class="u-item-label min-w-0 truncate">{{ row.site }}</span>
					<span class="u-item-detail shrink-0">
						{{ row.size_text }} · {{ row.files }} files<template v-if="row.oldest_days">
							· oldest {{ row.oldest_days }}d</template>
					</span>
				</li>
			</ul>
		</div>
	</section>
</template>

<script setup>
import { computed, h } from "vue";
import Icon from "./Icon.vue";

const props = defineProps({ data: { type: Object, default: null } });

/**
 * A bar plus a number, in that order of prominence.
 *
 * The bar is the thing you read at a glance across four panels; the percentage
 * is what you read once something looks wrong. Both are needed — a bar alone
 * cannot distinguish 91% from 96%, and on a nearly-full disk that is the whole
 * question.
 */
const Gauge = (p) =>
	h("div", { class: "bg-[var(--paper)] px-4 py-3" }, [
		h("div", { class: "flex items-baseline justify-between gap-2" }, [
			h("span", { class: "u-label" }, p.label),
			h("span", { class: `text-[13px] font-medium tabular-nums ${toneFor(p.level)}` }, p.value),
		]),
		h("div", { class: "mt-2 h-1.5 overflow-hidden rounded-full bg-[var(--paper-sunk)]" }, [
			h("div", {
				class: `h-full rounded-full transition-all duration-500 ${fillFor(p.level)}`,
				style: { width: `${Math.min(100, Math.max(2, p.percent))}%` },
			}),
		]),
		h("p", { class: "u-item-detail mt-1.5 leading-snug" }, p.detail),
	]);
Gauge.props = ["label", "value", "percent", "detail", "level"];

function toneFor(level) {
	return level === "critical" ? "u-danger" : level === "warn" ? "u-warn" : "text-[var(--ink)]";
}

function fillFor(level) {
	if (level === "critical") return "bg-[var(--danger)]";
	if (level === "warn") return "bg-[var(--warn)]";
	return "bg-[var(--ink)]";
}

function chipFor(level) {
	return level === "critical" ? "u-chip-danger" : "u-chip-warn";
}

const gauges = computed(() => {
	const d = props.data;
	if (!d) return [];
	const out = (d.disks || []).map((disk) => ({
		label: d.disks.length > 1 ? `disk ${disk.label}` : "disk",
		value: `${disk.percent}%`,
		percent: disk.percent,
		detail: disk.detail,
		level: disk.level,
	}));
	if (d.memory?.percent != null) {
		out.push({
			label: "memory",
			value: `${d.memory.percent}%`,
			percent: d.memory.percent,
			detail: d.memory.detail,
			level: d.memory.level,
		});
	}
	if (d.swap?.percent != null) {
		out.push({
			label: "swap",
			value: `${d.swap.percent}%`,
			percent: d.swap.percent,
			detail: d.swap.detail,
			level: d.swap.level,
		});
	}
	if (d.load) {
		out.push({
			label: "load",
			value: d.load.one.toFixed(2),
			// Per CPU, so the bar means the same thing on a 2-core box and a
			// 16-core one. A raw load average does not.
			percent: d.load.per_cpu * 100,
			detail: `${d.load.detail} · ${d.load.five} / ${d.load.fifteen} over 5 and 15 min`,
			level: d.load.level,
		});
	}
	return out;
});
</script>
