import { expect, test as base } from '@playwright/test';
import { LOAD_SCENARIOS } from './transport-load.mjs';
import { loadServer } from './wasm-servers.mjs';

type LoadRuntime = typeof globalThis & {
	runTransportLoad(options: Record<string, number | boolean>): Promise<{
		failures: string[];
		completed: number;
		cancelled: number;
		refused: number;
		dispatched: number;
		freed: number;
		setups: number;
	}>;
	transportLoadProgress?(): Record<string, unknown>;
};

// Each worker serves the load page once. A first local run also compiles its Wasm build.
const test = base.extend<object, { loadPage: string }>({
	loadPage: [
		async ({}, use) => {
			const server = await loadServer();
			try {
				await use(server.url);
			} finally {
				await server.close();
			}
		},
		{ scope: 'worker', timeout: 420_000 }
	]
});

test.describe('real encrypted Fetch requests', () => {
	test.beforeEach(async ({ page, loadPage }) => {
		await page.goto(loadPage);
		await page.waitForFunction(
			() => typeof (globalThis as LoadRuntime).runTransportLoad === 'function'
		);
	});

	// A failed or stalled run attaches its counts and the last phase of each unfinished request.
	test.afterEach(async ({ page }, testInfo) => {
		if (testInfo.status === testInfo.expectedStatus) return;
		const progress = await page.evaluate(() =>
			(globalThis as LoadRuntime).transportLoadProgress?.()
		);
		await testInfo.attach('progress', {
			body: JSON.stringify(progress, null, 2),
			contentType: 'application/json'
		});
	});

	for (const [name, options] of Object.entries(LOAD_SCENARIOS)) {
		test(name, async ({ page }) => {
			// Firefox takes up to about 13 seconds for the streaming case on two cores.
			if ('stream' in options) test.slow();
			const result = await page.evaluate(
				(options) => (globalThis as LoadRuntime).runTransportLoad(options),
				options
			);
			expect(result.failures).toEqual([]);
			expect(result.completed + result.cancelled).toBe(options.requests);
			// Each refused request is sent once more.
			expect(result.dispatched).toBe(options.requests + result.refused);
			expect(result.freed).toBe(result.setups);
			if ('cancelEvery' in options) expect(result.setups).toBe(1);
			if ('drainAfter' in options) {
				expect(result.refused).toBeGreaterThan(0);
				expect(result.setups).toBeGreaterThan(1);
			} else expect(result.refused).toBe(0);
		});
	}
});
