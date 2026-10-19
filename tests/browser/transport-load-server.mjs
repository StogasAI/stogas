import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { promisify } from 'node:util';

const root = resolve(import.meta.dirname, '../..');
const execute = promisify(execFile);

export async function loadServer() {
	const directory = await mkdtemp(join(tmpdir(), 'stogas-client-load-'));
	const env = {
		...process.env,
		PATH: `${resolve(process.env.CARGO_HOME ?? resolve(homedir(), '.cargo'), 'bin')}${delimiter}${process.env.PATH ?? ''}`
	};
	let server;
	try {
		const { stdout } = await execute(
			'cargo',
			[
				'test',
				'--locked',
				'--release',
				'--package',
				'stogas-wasm',
				'--lib',
				'--target',
				'wasm32-unknown-unknown',
				'--features',
				'staging',
				'--no-run',
				'--message-format=json'
			],
			{ cwd: root, env, maxBuffer: 16 * 1024 * 1024 }
		);
		const artifact = stdout
			.split('\n')
			.filter((line) => line.startsWith('{'))
			.map((line) => JSON.parse(line))
			.find(
				(item) =>
					item.reason === 'compiler-artifact' &&
					item.target.name === 'stogas_wasm' &&
					item.profile.test
			);
		if (!artifact?.executable) throw new Error('Wasm test artifact was not produced');
		await execute(
			'wasm-bindgen',
			[artifact.executable, '--target', 'web', '--out-dir', directory, '--out-name', 'client_load'],
			{ cwd: root, env }
		);
		const files = new Map();
		for (const name of ['client_load.js', 'client_load_bg.wasm'])
			files.set(`/${name}`, await readFile(join(directory, name)));
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
const wasm=await init();
globalThis.runTransportLoad=options=>runLoad(api,options);
globalThis.transportWasmBytes=()=>wasm.memory.buffer.byteLength;
</script>`)
		);
		server = createServer((request, response) => {
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
			directory,
			async close() {
				server.closeAllConnections();
				await new Promise((resolve) => server.close(resolve));
				await rm(directory, { recursive: true, force: true });
			}
		};
	} catch (error) {
		server?.close();
		await rm(directory, { recursive: true, force: true });
		throw error;
	}
}
