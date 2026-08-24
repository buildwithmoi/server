import path from "path";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import frappeui from "frappe-ui/vite";
import proxyOptions from "./proxyOptions";

// https://vitejs.dev/config/
export default defineConfig({
	plugins: [
		// Only the icon resolver is taken from frappe-ui. Its proxy, Jinja
		// boot-data injection and build config are all disabled because this
		// SPA already has doppio's versions of those wired up, and letting both
		// write the same settings is how you get a build that works locally and
		// 404s in production.
		frappeui({
			frappeProxy: false,
			jinjaBootData: false,
			buildConfig: false,
		}),
		vue(),
	],
	server: {
		port: 8080,
		host: "0.0.0.0",
		proxy: proxyOptions,
	},
	resolve: {
		alias: {
			"@": path.resolve(__dirname, "src"),
		},
	},
	build: {
		outDir: "../server/public/serving",
		emptyOutDir: true,
		target: "es2015",
	},
});
