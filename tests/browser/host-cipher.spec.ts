import { expect, test as base } from '@playwright/test';
import { testRunner } from './wasm-servers.mjs';

const PACKAGES = ['stogas-wasm', 'stogas-core'];

// The optimized Wasm library tests that CI also runs in Node exercise the private
// adapter and cancellation state, and the full cryptographic vector sets, in each
// browser engine without shipping test exports.
const test = base.extend<object, { runners: Record<string, string> }>({
	// Each worker starts the runners once. A first local run also compiles the tests.
	runners: [
		async ({}, use) => {
			const started: Awaited<ReturnType<typeof testRunner>>[] = [];
			try {
				for (const cargoPackage of PACKAGES) started.push(await testRunner(cargoPackage));
				await use(Object.fromEntries(PACKAGES.map((name, index) => [name, started[index].url])));
			} finally {
				for (const runner of started) await runner.close();
			}
		},
		{ scope: 'worker', timeout: 720_000 }
	]
});

for (const cargoPackage of PACKAGES) {
	test(`${cargoPackage}: cryptography contracts hold`, async ({ page, runners }) => {
		// The vector sets take up to about five seconds in an engine on a fast machine.
		test.slow();
		const errors: string[] = [];
		page.on('pageerror', (error) => errors.push(error.message));
		await page.goto(runners[cargoPackage]);
		// Only the test's time limit bounds the run; a page error ends it at once.
		await expect
			.poll(
				() => {
					if (errors.length) throw new Error(errors.join('; '));
					return page.locator('body').innerText();
				},
				{ timeout: 0 }
			)
			.toContain('test result:');
		await expect(page.locator('body')).toContainText(/test result: ok\. [1-9]\d* passed; 0 failed/);
	});
}
