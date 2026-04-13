import { defineConfig } from 'vitest/config';
import oxc from 'unplugin-oxc/vite';

export default defineConfig({
  plugins: [
    oxc({
      transform: {
        decoratorMetadata: true,
      },
    }),
  ],
  test: {
    globals: true,
    include: ['lib/**/*.spec.ts', 'lib/**/*.test.ts'],
    coverage: {
      include: ['lib/**/*.{js,jsx,tsx,ts}'],
      exclude: ['**/node_modules/**', '**/vendor/**'],
      reporter: ['json', 'lcov'],
    },
  },
});
