import { test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { extname, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '../..');
const TYPES: Record<string, string> = {
	'.js': 'text/javascript',
	'.mjs': 'text/javascript',
	'.wasm': 'application/wasm'
};

// STOGAS_LIVE=staging|prod serves the browser package from a local origin and
// reaches that environment's evidence and gateway origins.
test('live gateway rejects an invalid key through E2EE', async ({ page }) => {
	const environment = process.env.STOGAS_LIVE;
	test.skip(!environment, 'Set STOGAS_LIVE to staging or prod');
	const server = createServer((request, response) => {
		const path = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
		if (path === '/') return response.end('<!doctype html><title>SDK consumer</title>');
		const type = TYPES[extname(path)];
		if (!type || !/^\/(bindings|pkg\/browser|tests\/browser)\//.test(path)) {
			response.statusCode = 404;
			return response.end();
		}
		readFile(resolve(ROOT, `.${path}`)).then(
			(body) => response.setHeader('content-type', type).end(body),
			() => {
				response.statusCode = 404;
				response.end();
			}
		);
	});
	await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
	try {
		const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
		await page.goto(origin);
		await page.evaluate(
			async ({ origin, environment }) => {
				const sdk = await import(`${origin}/bindings/browser/browser.js`);
				const { checkLiveGateway } = await import(`${origin}/tests/browser/live.mjs`);
				await sdk.default();
				await checkLiveGateway(sdk.StogasTransport, environment);
			},
			{ origin, environment }
		);
	} finally {
		server.closeAllConnections();
		await new Promise<void>((done, fail) =>
			server.close((error) => (error ? fail(error) : done()))
		);
	}
});
