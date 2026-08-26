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
		path: "/domains",
		name: "DomainProviders",
		component: () => import("../views/DomainProviders.vue"),
		meta: { title: "Domain Providers" },
	},
	{
		path: "/github",
		name: "GitHubProfiles",
		component: () => import("../views/GitHubProfiles.vue"),
		meta: { title: "GitHub Accounts" },
	},
	{
		path: "/servers",
		name: "Servers",
		component: () => import("../views/Servers.vue"),
		meta: { title: "Servers" },
	},
	{
		path: "/dns",
		name: "DnsRecords",
		component: () => import("../views/DnsRecords.vue"),
		meta: { title: "DNS records" },
	},
	{
		path: "/migrations",
		name: "Migrations",
		component: () => import("../views/Migrations.vue"),
		meta: { title: "Bench moves" },
	},
	{
		path: "/migrations/:name",
		name: "Migration",
		component: () => import("../views/Migration.vue"),
		meta: { title: "Bench Move" },
	},
	{
		path: "/logs/deployments",
		name: "DeploymentLogs",
		component: () => import("../views/JobLogs.vue"),
		props: { kind: "deployment" },
		meta: { title: "Bench Deployment" },
	},
	{
		path: "/logs/ssl",
		name: "SslLogs",
		component: () => import("../views/JobLogs.vue"),
		props: { kind: "ssl" },
		meta: { title: "SSL Certificates" },
	},
	{
		path: "/logs/installs",
		name: "InstallLogs",
		component: () => import("../views/JobLogs.vue"),
		props: { kind: "install" },
		meta: { title: "App Installs" },
	},
	{
		path: "/logs/commands",
		name: "CommandLogs",
		component: () => import("../views/JobLogs.vue"),
		props: { kind: "command" },
		meta: { title: "Commands" },
	},
	{
		path: "/logs/scheduled",
		name: "ScheduledLogs",
		component: () => import("../views/ScheduledLogs.vue"),
		meta: { title: "Background work" },
	},
	{
		path: "/logs/crashes",
		name: "CrashLogs",
		component: () => import("../views/CrashLogs.vue"),
		meta: { title: "Crashes" },
	},
	{
		path: "/logs/restores",
		name: "RestoreLogs",
		component: () => import("../views/JobLogs.vue"),
		props: { kind: "restore" },
		meta: { title: "Bench Restoration" },
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
