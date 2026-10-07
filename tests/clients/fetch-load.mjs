// Real Rust/Wasm records through the production Fetch scheduler in Node, Bun and Deno.
// Synthetic session setup avoids network trust and provider dependencies.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadServer } from '../browser/transport-load-server.mjs';
import { runLoad } from '../browser/transport-load.mjs';

const server = await loadServer();
try {
	const api = await import(pathToFileURL(join(server.directory, 'client_load.js')));
	await api.default({
		module_or_path: await readFile(join(server.directory, 'client_load_bg.wasm'))
	});
	for (const options of [
		{ maxConnections: 1, requests: 300, concurrency: 257, ackDelayMs: 2 },
		{
			maxConnections: 4,
			requests: 96,
			concurrency: 32,
			stream: true,
			responseBytes: 131072,
			slowReaderMs: 1
		},
		{ maxConnections: 1, requests: 64, concurrency: 16, providerDelayMs: 2, cancelEvery: 3 },
		{
			maxConnections: 1,
			concurrency: 16,
			requests: 96,
			responseBytes: 131072,
			slowReaderMs: 2,
			retireEvery: 8
		}
	]) {
		const result = await runLoad(api, options);
		assert.deepEqual(result.failures, []);
		assert.equal(result.completed + result.cancelled, options.requests);
		assert.equal(result.dispatched, options.requests);
		assert.equal(result.freed, result.setups);
		if (options.cancelEvery) assert.equal(result.setups, 1);
		if (options.retireEvery) assert.ok(result.setups > 1);
		console.log(JSON.stringify({ options, ...result }));
	}
} finally {
	await server.close();
}
