import { defineConfig } from 'vite';

export default defineConfig({
  base: '/',
  build: {
    outDir: '../static',
    emptyOutDir: true,
    chunkSizeWarningLimit: 3000,
  },
});
