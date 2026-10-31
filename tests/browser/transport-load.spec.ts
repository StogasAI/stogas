import { chromium, firefox, webkit, expect, test } from '@playwright/test';
import { loadServer } from './transport-load-server.mjs';

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

const SCENARIOS = [
	{ maxConnections: 1, concurrency: 257, requests: 300, ackDelayMs: 2 },
	{
		maxConnections: 4,
		concurrency: 32,
		requests: 96,
		stream: true,
		responseBytes: 131072,
		recordBytes: 256,
		slowReaderMs: 1
	},
	{ maxConnections: 1, concurrency: 16, requests: 64, providerDelayMs: 2, cancelEvery: 3 },
	{
		maxConnections: 1,
		concurrency: 16,
		requests: 96,
		responseBytes: 131072,
		slowReaderMs: 2,
		drainAfter: 8
	}
];

// Each browser is its own test, and every wait has its own limit, so a stall names its browser
// and what it waited for. A scenario takes at most about 20 seconds on two cores.
for (const engine of [chromium, firefox, webkit]) {
	test(`real encrypted Fetch requests wait for capacity, stream, cancel and release ownership in ${engine.name()}`, async () => {
		// A first local run also builds the Wasm test artifact.
		test.setTimeout(480_000);
		const server = await loadServer();
		try {
			const browser = await engine.launch();
			try {
				const page = await browser.newPage();
				page.on('pageerror', (error) => console.log(`${engine.name()}: ${error.stack}`));
				page.on('crash', () => console.log(`${engine.name()}: the page crashed`));
				await page.goto(server.url, { timeout: 60_000 });
				await page.waitForFunction(
					() => typeof (globalThis as LoadRuntime).runTransportLoad === 'function',
					undefined,
					{ timeout: 60_000 }
				);
				for (const options of SCENARIOS) {
					try {
						await test.step(
							JSON.stringify(options),
							async () => {
								const started = Date.now();
								const result = await page.evaluate(
									(options) => (globalThis as LoadRuntime).runTransportLoad(options),
									options
								);
								console.log(
									`${engine.name()} ${JSON.stringify(options)}: ${Date.now() - started} ms`
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
							},
							{ timeout: 120_000 }
						);
					} catch (error) {
						// The page's own account of the stall; a page that cannot answer is busy or hung.
						const progress = await Promise.race([
							page.evaluate(() => (globalThis as LoadRuntime).transportLoadProgress?.()),
							new Promise((resolve) => setTimeout(resolve, 5_000, 'no answer from the page'))
						]).catch(String);
						console.log(`${engine.name()} ${JSON.stringify(options)}: ${JSON.stringify(progress)}`);
						throw error;
					}
				}
			} finally {
				await test.step('close the browser', () => browser.close(), { timeout: 60_000 });
			}
		} finally {
			await test.step('stop the page server', () => server.close(), { timeout: 30_000 });
		}
	});
}
