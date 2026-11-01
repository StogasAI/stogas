import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
	fullyParallel: true,
	forbidOnly: true,
	reporter: 'list',
	retries: 0,
	testDir: '.',
	use: { trace: 'retain-on-failure' },
	projects: [
		{ name: 'chromium', use: devices['Desktop Chrome'] },
		{ name: 'firefox', use: devices['Desktop Firefox'] },
		{
			name: 'webkit',
			use: {
				...devices['Desktop Safari'],
				// Playwright's WebKit builds 2370 and 2387 sometimes stop a page for good inside
				// JavaScriptCore's garbage collector on four cores, as on GitHub's runners: about one
				// drain scenario run in 60. Marking with one thread made it about one in 1,100, and
				// no test depends on parallel marking. Replacing the environment keeps the rest of it.
				launchOptions: { env: { ...process.env, JSC_numberOfGCMarkers: '1' } }
			}
		}
	]
});
