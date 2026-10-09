// Real production Wasm request objects and Fetch scheduling, with a synthetic
// prepared peer. Both endpoints run here; this excludes WAN and fresh SNP quotes.
import { SessionTransport } from '../../bindings/shared/session-transport.js';
import { SESSION_CONTENT_TYPE } from '../../bindings/shared/channel-http.js';

const encode = (value) => new TextEncoder().encode(value);
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function runLoad(
	api,
	{
		maxConnections = 4,
		concurrency = 4,
		requests = 128,
		requestBytes = 4096,
		responseBytes = 4096,
		recordBytes = 65_515,
		ackDelayMs = 0,
		providerDelayMs = 0,
		slowReaderMs = 0,
		stream = false,
		cancelEvery = 0,
		retireEvery = 0
	} = {}
) {
	const peers = new Map();
	// Vary server fragmentation without changing the real client record codec.
	if (!Number.isInteger(recordBytes) || recordBytes < 1 || recordBytes > 65_515)
		throw new RangeError('recordBytes exceeds the encrypted record bound');
	const counts = {
		setups: 0,
		freed: 0,
		dispatched: 0,
		responsesFreed: 0,
		closes: 0,
		acknowledged: 0,
		completed: 0,
		cancelled: 0,
		peakRequests: 0
	};
	let active = 0;
	const payload = JSON.stringify({ input: 'q'.repeat(requestBytes), stream });
	const data = encode(
		stream
			? `data: ${JSON.stringify({ choices: [{ delta: { content: 'r'.repeat(responseBytes) } }] })}\n\ndata: [DONE]\n\n`
			: JSON.stringify({ output: 'r'.repeat(responseBytes) })
	);
	class Setup {
		hello = new Uint8Array([1]);
		complete() {
			const channel = new api.TestChannel();
			const node = `test-${counts.setups++}`;
			peers.set(node, channel);
			return {
				node_id: node,
				idle_seconds: 600,
				request: () => channel.request(),
				close: () => channel.close(),
				free() {
					channel.free();
					peers.delete(node);
					counts.freed++;
				}
			};
		}
		free() {}
	}
	const transport = new SessionTransport({
		Setup,
		maxSessions: maxConnections,
		environment: 'staging',
		endpoint: 'https://fixture.example/v1/session',
		evidence: { check: (use) => use(undefined) },
		async fetch(_url, options) {
			if (options.body instanceof Uint8Array)
				return new Response(new Uint8Array([1]), {
					headers: { 'content-type': SESSION_CONTENT_TYPE }
				});
			if (new Headers(options.headers).has('authorization'))
				throw new Error('outer credential leak');
			const peer = peers.get(new Headers(options.headers).get('stogas-node-id'));
			const response = peer.accept(new Uint8Array(await options.body.arrayBuffer()));
			if (response.close) counts.closes++;
			else {
				counts.dispatched++;
				if (response.request_bytes !== encode(payload).length) {
					const actual = response.request_bytes;
					response.free();
					counts.responsesFreed++;
					throw new Error(`upload mismatch: ${actual} != ${encode(payload).length}`);
				}
			}
			const closing = !response.close && retireEvery > 0 && counts.dispatched % retireEvery === 0;
			let closed = false,
				phase = 0,
				offset = 0;
			const finish = () => {
				if (!closed) {
					closed = true;
					response.free();
					counts.responsesFreed++;
				}
			};
			return new Response(
				new ReadableStream({
					async pull(controller) {
						try {
							if (phase === 0) {
								phase++;
								if (ackDelayMs) await delay(ackDelayMs);
								if (!closed) controller.enqueue(response.seal(4, new Uint8Array()));
							} else if (phase === 1) {
								phase++;
								if (providerDelayMs) await delay(providerDelayMs);
								if (!closed)
									controller.enqueue(
										response.seal(
											1,
											encode(
												JSON.stringify({
													status: response.close ? 204 : 200,
													closing,
													headers: response.close
														? {}
														: { 'content-type': stream ? 'text/event-stream' : 'application/json' }
												})
											)
										)
									);
							} else if (!response.close && offset < data.length) {
								const end = Math.min(offset + recordBytes, data.length);
								controller.enqueue(response.seal(2, data.subarray(offset, end)));
								offset = end;
							} else {
								controller.enqueue(response.seal(3, new Uint8Array()));
								controller.close();
								finish();
							}
						} catch (error) {
							controller.error(error);
							finish();
						}
					},
					cancel: finish
				}),
				{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
			);
		}
	});
	const latencies = [];
	const failures = [];
	let next = 0;
	const start = performance.now();
	try {
		await Promise.all(
			Array.from({ length: concurrency }, async () => {
				for (;;) {
					const number = next++;
					if (number >= requests) return;
					const started = performance.now();
					const controller = new AbortController();
					const cancelling = cancelEvery > 0 && number % cancelEvery === 0;
					active++;
					counts.peakRequests = Math.max(active, counts.peakRequests);
					try {
						const response = await transport.send(
							new Request('https://fixture.example/v1/chat/completions', {
								method: 'POST',
								body: payload,
								signal: controller.signal,
								headers: { authorization: 'Bearer private-test-key' }
							}),
							(phase) => {
								if (phase === 'acknowledged') {
									counts.acknowledged++;
									if (cancelling) controller.abort();
								}
							}
						);
						if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
						const reader = response.body.getReader();
						let size = 0;
						try {
							for (;;) {
								const chunk = await reader.read();
								if (chunk.done) break;
								size += chunk.value.length;
								if (slowReaderMs) await delay(slowReaderMs);
							}
						} finally {
							reader.releaseLock();
						}
						if (size !== data.length) throw new Error(`response bytes ${size} != ${data.length}`);
						if (cancelling) throw new Error('cancelled request completed');
						counts.completed++;
					} catch (error) {
						if (cancelling && controller.signal.aborted && error.submission === 'execution_unknown')
							counts.cancelled++;
						else
							failures.push(
								[error, error.cause, error.cause?.cause]
									.filter(Boolean)
									.map((value) => `${value.name}: ${value.message}\n${value.stack ?? ''}`)
									.join('\ncaused by: ')
							);
					} finally {
						active--;
						latencies.push(performance.now() - started);
					}
				}
			})
		);
	} finally {
		await transport.close();
	}
	const durationMs = performance.now() - start;
	latencies.sort((a, b) => a - b);
	if (
		counts.freed !== counts.setups ||
		peers.size ||
		counts.responsesFreed !== counts.dispatched + counts.closes
	)
		throw new Error(
			`retained fixture ownership: ${JSON.stringify(counts)}; failures: ${JSON.stringify(failures.slice(0, 2))}`
		);
	return {
		...counts,
		failures,
		durationMs,
		requestsPerSecond: (requests * 1000) / durationMs,
		p50Ms: latencies[Math.floor(latencies.length * 0.5)],
		p99Ms: latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * 0.99))],
		maximumMs: latencies.at(-1)
	};
}
