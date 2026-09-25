import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// In development and preview, proxy /api to a relay so the page is same-origin
// and no CORS preflight is needed. In production, point the app at a relay that
// sends CORS headers (see docs/DEPLOY.md), or serve the built app from the relay.
const relayTarget = process.env.NK_RELAY ?? 'http://127.0.0.1:8000';
const proxy = { '/api': { target: relayTarget, changeOrigin: true } };

export default defineConfig({
  plugins: [react()],
  base: './',
  build: { target: 'es2022', outDir: 'dist', sourcemap: true },
  server: { host: '127.0.0.1', port: 5173, strictPort: true, proxy },
  preview: { host: '127.0.0.1', port: 4173, strictPort: true, proxy },
});
