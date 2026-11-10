import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import { mount } from "svelte";
import App from "./App.svelte";
import "./app.css";
import { initTheme } from "./lib/stores/theme";

// Re-applies the Appearance preference `public/theme-boot.js` already set
// before first paint, and keeps "system" live while the window stays open.
initTheme();

mount(App, { target: document.getElementById("app")! });
