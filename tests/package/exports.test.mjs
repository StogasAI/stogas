// Run from a project that installed both npm packages: it resolves every entry point by package
// name, as dependents do, under the conditions of both import and require.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);

for (const name of ['stogas', '@stogas/sigstore']) {
	test(`${name} resolves every entry point by name`, () => {
		const manifest = require(`${name}/package.json`);
		assert.equal(manifest.name, name);
		const root = require.resolve(`${name}/package.json`).slice(0, -'package.json'.length);
		for (const [subpath, target] of Object.entries(manifest.exports)) {
			const specifier = name + subpath.slice(1);
			const resolved = require.resolve(specifier);
			assert.equal(fileURLToPath(import.meta.resolve(specifier)), resolved, specifier);
			assert.ok(existsSync(resolved), specifier);
			if (typeof target === 'object')
				assert.ok(existsSync(root + target.types), `${specifier} types`);
		}
	});

	test(`${name} loads with import and require`, async () => {
		const imported = await import(name);
		const required = require(name);
		assert.notEqual(Object.keys(imported).length, 0);
		for (const key of Object.keys(imported)) assert.equal(required[key], imported[key], key);
	});
}
