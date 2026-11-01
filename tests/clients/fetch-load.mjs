// Real Rust/Wasm records through the production Fetch scheduler in Node, Bun and Deno.
// Synthetic session setup avoids network trust and provider dependencies.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadClient } from '../browser/wasm-servers.mjs';
import { LOAD_SCENARIOS, runLoad } from '../browser/transport-load.mjs';

const client = await loadClient();
try {
	const api = await import(pathToFileURL(join(client.directory, 'client_load.js')));
	await api.default({
		module_or_path: await readFile(join(client.directory, 'client_load_bg.wasm'))
	});
	for (const [name, options] of Object.entries(LOAD_SCENARIOS)) {
		const result = await runLoad(api, options);
		assert.deepEqual(result.failures, [], name);
		assert.equal(result.completed + result.cancelled, options.requests, name);
		// Each refused request is sent once more.
		assert.equal(result.dispatched, options.requests + result.refused, name);
		assert.equal(result.freed, result.setups, name);
		if (options.cancelEvery) assert.equal(result.setups, 1, name);
		if (options.drainAfter) assert.ok(result.refused > 0 && result.setups > 1, name);
		else assert.equal(result.refused, 0, name);
		console.log(JSON.stringify({ name, ...result }));
	}
} finally {
	await client.close();
}
