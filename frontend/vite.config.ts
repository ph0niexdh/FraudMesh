import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backend = process.env.VITE_BACKEND_URL ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: { react: ["react", "react-dom", "react-router-dom"], charts: ["recharts"], graph: ["cytoscape"] },
      },
    },
  },
  server: {
    port: 5173,
    host: true,
    proxy: {
      "/api": { target: backend, changeOrigin: true },
      "/ws": { target: backend.replace(/^http/, "ws"), ws: true },
    },
  },
});
