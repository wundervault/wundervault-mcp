import { defineConfig, configDefaults } from 'vitest/config';

// The build/review loop stages whole candidate files under .buildreview*/ — including tests.
// They are working copies, not the suite, and must never run as if they were.
export default defineConfig({
  test: { exclude: [...configDefaults.exclude, '.buildreview*/**'] },
});
