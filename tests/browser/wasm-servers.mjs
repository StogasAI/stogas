import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { promisify } from 'node:util';

const root = resolve(import.meta.dirname, '../..');
const execute = promisify(execFile);
const environment = {
	...process.env,
	PATH: `${resolve(process.env.CARGO_HOME ?? resolve(homedir(), '.cargo'), 'bin')}${delimiter}${process.env.PATH ?? ''}`
};

// A package's optimized Wasm library tests. CI builds them before the browser tests;
// a first local run compiles them here.
async function testArtifact(cargoPackage, features = []) {
	const { stdout } = await execute(
		'cargo',
		[
			'test',
			'--locked',
			'--profile',
			'wasm',
			'--package',
			cargoPackage,
			'--lib',
			'--target',
			'wasm32-unknown-unknown',
			...features.flatMap((feature) => ['--features', feature]),
			'--no-run',
			'--message-format=json'
		],
		// Bounded, so a stalled build fails with its own output.
		{ cwd: root, env: environment, maxBuffer: 16 * 1024 * 1024, timeout: 300_000 }
	);
	const artifact = stdout
		.split('\n')
		.filter((line) => line.startsWith('{'))
		.map((line) => JSON.parse(line))
		.find(
			(item) =>
				item.reason === 'compiler-artifact' &&
				item.target.name === cargoPackage.replaceAll('-', '_') &&
				item.profile.test
		);
	if (!artifact?.executable) throw new Error(`${cargoPackage}: no Wasm test artifact`);
	return artifact.executable;
}

// The staging adapter's test build, which exports TestChannel, as a web module.
export async function loadClient() {
	const directory = await mkdtemp(join(tmpdir(), 'stogas-client-load-'));
	try {
		await execute(
			'wasm-bindgen',
			[
				await testArtifact('stogas-wasm', ['staging']),
				'--target',
				'web',
				'--out-dir',
				directory,
				'--out-name',
				'client_load'
			],
			{ cwd: root, env: environment, timeout: 60_000 }
		);
		return { directory, close: () => rm(directory, { recursive: true, force: true }) };
	} catch (error) {
		await rm(directory, { recursive: true, force: true });
		throw error;
	}
}

// A page that runs transport-load.mjs with that build and the shared bindings.
export async function loadServer() {
	const files = new Map();
	const client = await loadClient();
	try {
		for (const name of ['client_load.js', 'client_load_bg.wasm'])
			files.set(`/${name}`, await readFile(join(client.directory, name)));
	} finally {
		await client.close();
	}
	files.set(
		'/tests/browser/transport-load.mjs',
		await readFile(join(root, 'tests/browser/transport-load.mjs'))
	);
	for (const name of await readdir(join(root, 'bindings/shared')))
		if (name.endsWith('.js'))
			files.set(`/bindings/shared/${name}`, await readFile(join(root, 'bindings/shared', name)));
	files.set(
		'/',
		Buffer.from(`<!doctype html><script type="module">
import init,* as api from '/client_load.js';
import {runLoad} from '/tests/browser/transport-load.mjs';
await init();
globalThis.runTransportLoad=options=>runLoad(api,options);
</script>`)
	);
	const server = createServer((request, response) => {
		const body = files.get(request.url);
		if (!body) {
			response.writeHead(404).end();
			return;
		}
		response.setHeader(
			'content-type',
			request.url.endsWith('.wasm')
				? 'application/wasm'
				: request.url === '/'
					? 'text/html'
					: 'text/javascript'
		);
		response.end(body);
	});
	await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
	return {
		url: `http://127.0.0.1:${server.address().port}`,
		async close() {
			server.closeAllConnections();
			await new Promise((resolve) => server.close(resolve));
		}
	};
}

// wasm-bindgen's interactive runner serves a page that runs a package's Rust tests
// in the browser that opens it.
export async function testRunner(cargoPackage) {
	const runner = spawn('wasm-bindgen-test-runner', [await testArtifact(cargoPackage)], {
		cwd: root,
		env: {
			...environment,
			WASM_BINDGEN_USE_BROWSER: '1',
			NO_HEADLESS: '1',
			WASM_BINDGEN_TEST_ADDRESS: '127.0.0.1:0'
		},
		stdio: ['ignore', 'pipe', 'pipe']
	});
	const exited = once(runner, 'exit');
	try {
		const url = await new Promise((resolve, reject) => {
			let output = '';
			const deadline = setTimeout(
				() => reject(new Error(`${cargoPackage}: the Wasm test runner did not start: ${output}`)),
				30_000
			);
			runner.on('error', (error) => {
				clearTimeout(deadline);
				reject(error);
			});
			runner.on('exit', (code) => {
				clearTimeout(deadline);
				reject(new Error(`${cargoPackage}: the Wasm test runner exited (${code}): ${output}`));
			});
			runner.stderr.on('data', (bytes) => {
				output += bytes.toString();
			});
			runner.stdout.on('data', (bytes) => {
				output += bytes.toString();
				const match = output.match(
					/Interactive browsers tests are now available at (http:\/\/127\.0\.0\.1:\d+)/
				);
				if (match) {
					clearTimeout(deadline);
					resolve(match[1]);
				}
			});
		});
		return {
			url,
			async close() {
				runner.kill();
				await exited;
			}
		};
	} catch (error) {
		runner.kill();
		await exited.catch(() => {});
		throw error;
	}
}
