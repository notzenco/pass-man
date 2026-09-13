import { defineConfig } from "vite";

// Tauri expects a fixed port and does not want Vite to obscure Rust errors.
export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    target: "es2022",
    sourcemap: true,
  },
});
