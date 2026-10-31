import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import solid from 'vite-plugin-solid';

const platformEntry = process.env.BUILD_TARGET === 'tauri'
  ? './src/platform/tauri/index.ts'
  : './src/platform/web/index.ts';

export default defineConfig({
  plugins: [solid()],
  resolve: {
    alias: [
      { find: /^@platform$/, replacement: fileURLToPath(new URL(platformEntry, import.meta.url)) },
      { find: '@platform/', replacement: fileURLToPath(new URL('./src/platform/', import.meta.url)) },
    ],
  },
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: 'vault',
          environment: 'node',
          include: ['src/lib/vault/**/*.test.ts'],
          setupFiles: ['fake-indexeddb/auto'],
        },
      },
      {
        extends: true,
        test: {
          name: 'components',
          environment: 'jsdom',
          include: ['src/components/**/*.test.{ts,tsx}'],
          setupFiles: ['fake-indexeddb/auto'],
        },
      },
    ],
  },
});
