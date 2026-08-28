import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Chaperone dashboard (Phase 12): Vite + React + TS + Tailwind v4 (dark
// terminal aesthetic, docs/tech-stack.md). Dev server proxies /v1 + /ws to
// the gate so the dashboard talks to a running `chaperone serve`.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/v1": {
        target: process.env.CHAPERONE_URL ?? "http://127.0.0.1:8400",
        changeOrigin: true,
      },
      "/ws": {
        target: process.env.CHAPERONE_URL ?? "http://127.0.0.1:8400",
        ws: true,
      },
    },
  },
});
