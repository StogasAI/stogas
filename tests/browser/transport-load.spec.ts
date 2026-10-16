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
};

test('real encrypted Fetch requests wait for capacity, stream, cancel and release ownership in every browser', async () => {
	test.setTimeout(480_000);
	const server = await loadServer();
	try {
		for (const engine of [chromium, firefox, webkit]) {
			const browser = await engine.launch();
			try {
				const page = await browser.newPage();
				await page.goto(server.url);
				await page.waitForFunction(
					() => typeof (globalThis as LoadRuntime).runTransportLoad === 'function'
				);
				for (const options of [
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
				]) {
					const result = await page.evaluate(
						(options) => (globalThis as LoadRuntime).runTransportLoad(options),
						options
					);
					expect(result.failures, `${engine.name()}: ${JSON.stringify(options)}`).toEqual([]);
					expect(result.completed + result.cancelled).toBe(options.requests);
					// Each refused request is sent once more.
					expect(result.dispatched).toBe(options.requests + result.refused);
					expect(result.freed).toBe(result.setups);
					if ('cancelEvery' in options) expect(result.setups).toBe(1);
					if ('drainAfter' in options) {
						expect(result.refused).toBeGreaterThan(0);
						expect(result.setups).toBeGreaterThan(1);
					} else expect(result.refused).toBe(0);
				}
			} finally {
				await browser.close();
			}
		}
	} finally {
		await server.close();
	}
});
