import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "./", // loaded from file:// in the packaged app
  build: { outDir: "dist", emptyOutDir: true, chunkSizeWarningLimit: 800, assetsInlineLimit: 0 }, // fonts stay files (CSP font-src 'self')
});
