import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    allowedHosts: ["localhost"],
    // Page is served at https://localhost via Caddy (port 443),
    // so HMR must connect back over wss on 443, not http on 5173.
    hmr: {
      host: "localhost",
      clientPort: 443,
      protocol: "wss",
    },
  },
});
