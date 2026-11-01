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
		{ name: 'webkit', use: devices['Desktop Safari'] }
	]
});
