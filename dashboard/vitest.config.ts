import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    env: {
      // Force the dev React build regardless of the ambient NODE_ENV
      // (the agent shell exports NODE_ENV=production, which breaks act()).
      NODE_ENV: "development",
    },
  },
});
