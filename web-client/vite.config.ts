import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../src/main/resources/web",
    emptyOutDir: true,
    // The three.js vendor chunk is 250 kB gzip and only loads with the portal
    // topology page, so the 500 kB default warning is not actionable here.
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/three") || id.includes("@react-three")) {
            return "three";
          }
          if (id.includes("node_modules/gsap") || id.includes("node_modules/lenis")) {
            return "motion";
          }
          if (id.includes("node_modules/react") || id.includes("node_modules/scheduler")) {
            return "react";
          }
          return undefined;
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test-setup.ts",
  },
});
