import { defineConfig } from "vitest/config";
export default defineConfig({
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8080",
        changeOrigin: false,
        configure(proxy) {
          proxy.on("proxyReq", (req) => req.removeHeader("cookie"));
        },
      },
    },
  },
  test: { include: ["src/**/*.test.ts"], maxWorkers: 1 },
});
