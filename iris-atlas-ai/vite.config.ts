import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig(({ mode }) => ({
  /* ── Root ── */
  root: '.',
  publicDir: 'public',

  /* ── Build output ── */
  build: {
    outDir: 'dist',
    emptyOutDir: true,

    /* Capacitor loads from file:// on Android — no code splitting */
    rollupOptions: {
      input: resolve(__dirname, 'index.html'),
      output: {
        /* Single-chunk output works best with Capacitor file:// */
        inlineDynamicImports: true,
        /* Asset naming */
        assetFileNames: 'assets/[name]-[hash][extname]',
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
      },
    },

    /* Larger chunk warning limit — app is intentionally large */
    chunkSizeWarningLimit: 4000,

    /* Source maps for debugging on device */
    sourcemap: mode === 'development',

    /* Minify for production */
    minify: mode !== 'development' ? 'esbuild' : false,

    /* Target modern Android WebView (Chromium 85+) */
    target: ['es2020', 'chrome85'],
  },

  /* ── Dev server ── */
  server: {
    port: 3000,
    open: false,
    cors: true,
    /* Allow Capacitor live reload to connect */
    hmr: { clientPort: 3000 },
  },

  /* ── Resolve ── */
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },

  /* ── Plugin ── (none needed; CDN scripts loaded in index.html) */
  plugins: [],

  /* ── Define global constants ── */
  define: {
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version ?? '4.0.0'),
    __BUILD_TIME__: JSON.stringify(new Date().toISOString()),
  },
}));
