import { createRouter, createWebHistory } from "vue-router";
import authRoutes from "./auth";

/**
 * Views are lazily imported so the first paint ships the shell and the
 * dashboard only. The log tables pull in their own chunk when first visited,
 * which keeps the initial bundle from growing every time a page is added.
 */
const routes = [
	{
		path: "/",
		name: "Dashboard",
		component: () => import("../views/Dashboard.vue"),
		meta: { title: "Overview" },
	},
	{
		path: "/security",
		name: "Security",
		component: () => import("../views/Security.vue"),
		meta: { title: "Security" },
	},
	{
		path: "/detectors",
		name: "Detectors",
		component: () => import("../views/Detectors.vue"),
		meta: { title: "Detectors" },
	},
	{
		path: "/sessions",
		name: "Sessions",
		component: () => import("../views/Sessions.vue"),
		meta: { title: "SSH Sessions" },
	},
	{
		path: "/auth-events",
		name: "AuthEvents",
		component: () => import("../views/AuthEvents.vue"),
		meta: { title: "SSH Events" },
	},
	{
		path: "/sudo",
		name: "SudoCommands",
		component: () => import("../views/SudoCommands.vue"),
		meta: { title: "Sudo Commands" },
	},
	{
		path: "/addresses",
		name: "IpAddresses",
		component: () => import("../views/IpAddresses.vue"),
		meta: { title: "Addresses" },
	},
	{
		path: "/benches",
		name: "Benches",
		component: () => import("../views/Benches.vue"),
		meta: { title: "Benches" },
	},
	{
		path: "/benches/:name",
		name: "BenchDetail",
		component: () => import("../views/BenchDetail.vue"),
		meta: { title: "Bench" },
	},
	{
		path: "/installs",
		name: "Installs",
		component: () => import("../views/Installs.vue"),
		meta: { title: "App Installs" },
	},
	{
		path: "/github",
		name: "GitHubProfiles",
		component: () => import("../views/GitHubProfiles.vue"),
		meta: { title: "GitHub Accounts" },
	},
	{
		path: "/settings",
		name: "Settings",
		component: () => import("../views/Settings.vue"),
		meta: { title: "Settings" },
	},
	...authRoutes,
];

const router = createRouter({
	history: createWebHistory("/serving"),
	routes,
	scrollBehavior: () => ({ top: 0 }),
});

export default router;
