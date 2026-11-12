import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` talks to the backend on :8000; `npm run build` writes the app into backend/static,
// which FastAPI then serves itself (so the finished project is ONE server on one port).
const api = "http://127.0.0.1:8000";
export default defineConfig({
  plugins: [react()],
  build: { outDir: "../backend/static", emptyOutDir: true },
  server: {
    port: 5173,
    proxy: {
      "/live": { target: api, ws: true },
      "/model/info": api,
      "/health": api,
      "/predict": api,
      "/events": api,
      "/stats": api,
      "/sample": api,
    },
  },
});
