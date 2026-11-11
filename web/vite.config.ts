import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development the browser talks to Vite, which forwards API calls to the server,
// so the app and API look like one origin, the same as in production.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:4000",
    },
  },
});
