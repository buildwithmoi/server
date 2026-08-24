/**
 * Monochrome theme.
 *
 * frappe-ui ships an opinionated colour system (blue accents, semantic
 * red/green/amber). This app is deliberately black and white, so the preset is
 * loaded for its component sizing, spacing and plugins, and every hue is then
 * overridden to a neutral ramp. Anything that must still read as a warning or a
 * failure is carried by weight, border and iconography instead of hue.
 */
import frappeUIPreset from "frappe-ui/tailwind";

export default {
	presets: [frappeUIPreset],
	content: [
		"./index.html",
		"./src/**/*.{vue,js,ts,jsx,tsx}",
		"./node_modules/frappe-ui/src/components/**/*.{vue,js,ts,jsx,tsx}",
		"./node_modules/frappe-ui/src/utils/**/*.{vue,js,ts,jsx,tsx}",
	],
	theme: {
		extend: {
			fontFamily: {
				sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
				mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
			},
		},
	},
};
