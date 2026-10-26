import assert from 'node:assert/strict';
import { test } from 'node:test';
import OpenAI from 'openai';
import { createTransportClass } from '../../bindings/shared/transport.js';
import { SESSION_CONTENT_TYPE } from '../../bindings/shared/channel-http.js';
import { Exchange, record, response } from './channel-fixture.mjs';

// Exercise the real OpenAI client through the shared public Fetch adapter.
// Crypto is doubled; the same wire and receipt rules have real Rust/Wasm vectors.
async function fixture(inference, maxRetries = 0) {
	let calls = 0;
	const exchanges = [];
	const Transport = createTransportClass({
		transport_configuration: () => ({
			environment: 'prod',
			e2ee_origin: 'https://gateway.example',
			evidence_origins: ['https://evidence.example/latest.json']
		}),
		EvidenceVerifier: class {
			static for_stogas() {
				return new this();
			}
			refresh() {
				return { summary: () => ({}), same_as: () => false, require_current_keys() {}, free() {} };
			}
			free() {}
		},
		EncryptedSetup: class {
			hello = new Uint8Array([99]);
			complete() {
				return {
					node_id: 'example-node',
					idle_seconds: 60,
					request() {
						const exchange = new Exchange();
						exchanges.push(exchange);
						return exchange;
					},
					close() {},
					free() {}
				};
			}
			free() {}
		}
	});
	const transport = await Transport.create({
		fetch: async (url, options) => {
			assert.equal(new Headers(options.headers).has('authorization'), false);
			if (url.includes('evidence.example')) return Response.json({});
			if (options.body instanceof Uint8Array)
				return new Response(new Uint8Array([1]), {
					headers: { 'content-type': SESSION_CONTENT_TYPE }
				});
			// Session disposal has no request DATA record.
			if (options.body.size === 5)
				return response([record(1, '{"status":204,"headers":{}}'), record(3)]);
			calls++;
			return inference();
		}
	});
	return {
		transport,
		exchanges,
		client: new OpenAI({ ...transport.openAIOptions('private-example-key'), maxRetries }),
		calls: () => calls
	};
}

const request = { model: 'example/model', messages: [{ role: 'user', content: 'hello' }] };

test('OpenAI owns retries after an acknowledged inner rejection, with a fresh encrypted exchange', async () => {
	for (const status of [429, 503]) {
		let attempts = 0;
		const state = await fixture(() => {
			const rejected = ++attempts === 1;
			return response([
				record(4),
				record(4),
				record(
					1,
					JSON.stringify({
						status: rejected ? status : 200,
						headers: { 'content-type': 'application/json', 'retry-after': '0.001' }
					})
				),
				record(
					2,
					JSON.stringify(
						rejected
							? { error: { message: 'Try again', type: 'server_error' } }
							: { choices: [{ message: { content: 'Hello' } }] }
					)
				),
				record(3)
			]);
		}, 1);
		try {
			assert.equal(
				(await state.client.chat.completions.create(request)).choices[0].message.content,
				'Hello'
			);
			assert.equal(state.calls(), 2);
			assert.equal(state.exchanges.length, 2);
			assert.notEqual(state.exchanges[0], state.exchanges[1]);
			for (const exchange of state.exchanges) assert.equal(exchange.freed, 1);
		} finally {
			await state.transport.close();
		}
	}
});

test('acknowledgement precedes inner headers, runs outside decoding and fires once', async () => {
	let output;
	let acknowledge;
	const acknowledged = new Promise((resolve) => {
		acknowledge = resolve;
	});
	let calls = 0;
	const state = await fixture(
		() =>
			new Response(
				new ReadableStream({
					start(controller) {
						output = controller;
						controller.enqueue(record(4));
					}
				}),
				{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
			)
	);
	let returned = false;
	const sending = state.transport
		.fetch(`${state.transport.baseURL}/chat/completions`, {
			method: 'POST',
			body: '{}',
			onProgress(phase) {
				if (phase !== 'acknowledged') return;
				calls++;
				assert.equal(state.exchanges[0].emitting, false);
				acknowledge();
				throw new Error('observer failure');
			}
		})
		.then((response) => {
			returned = true;
			return response;
		});
	await acknowledged;
	assert.equal(returned, false);
	output.enqueue(record(4));
	output.enqueue(
		record(
			1,
			'{"status":429,"headers":{"content-type":"application/json","retry-after":"7","x-should-retry":"false"}}'
		)
	);
	output.enqueue(record(2, '{"error":"later rejection"}'));
	output.enqueue(record(3));
	output.close();
	const response = await sending;
	assert.equal(response.status, 429);
	assert.equal(response.headers.get('retry-after'), '7');
	assert.equal(response.headers.get('x-should-retry'), 'false');
	assert.deepEqual(await response.json(), { error: 'later rejection' });
	assert.equal(calls, 1);
	assert.equal(state.exchanges[0].freed, 1);
	await state.transport.close();
});

test('outer IP rejection stays execution-unknown and OpenAI never resubmits it', async () => {
	for (const status of [429, 503]) {
		const state = await fixture(() =>
			Response.json(
				{ error: { code: 'ip_rate_limit_exceeded' } },
				{
					status,
					headers: { 'retry-after': '1' }
				}
			)
		);
		try {
			await assert.rejects(state.client.chat.completions.create(request), (error) => {
				assert.equal(error.cause?.submission, 'execution_unknown');
				return true;
			});
			assert.equal(state.calls(), 1);
		} finally {
			await state.transport.close();
		}
	}
});

test('OpenAI cancellation ends iteration, cancels the encrypted stream and never resends', async () => {
	let cancelled = 0;
	const content = { id: 'chat-1', choices: [{ index: 0, delta: { content: 'Hello' } }] };
	const state = await fixture(
		() =>
			new Response(
				new ReadableStream({
					start(controller) {
						controller.enqueue(
							record(
								1,
								JSON.stringify({ status: 200, headers: { 'content-type': 'text/event-stream' } })
							)
						);
						controller.enqueue(record(2, `data: ${JSON.stringify(content)}\n\n: waiting\n\n`));
					},
					cancel() {
						cancelled++;
					}
				}),
				{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
			)
	);
	const cancellation = new AbortController();
	try {
		const stream = await state.client.chat.completions.create(
			{ ...request, stream: true },
			{ signal: cancellation.signal }
		);
		const iterator = stream[Symbol.asyncIterator]();
		assert.equal((await iterator.next()).value.choices[0].delta.content, 'Hello');
		cancellation.abort();
		// The SDK ends iteration after a caller abort; the aborted signal tells the caller why.
		assert.deepEqual(await iterator.next(), { value: undefined, done: true });
		assert.equal(cancelled, 1);
		assert.equal(state.exchanges[0].freed, 1);
		assert.equal(state.calls(), 1);
	} finally {
		await state.transport.close();
	}
});

test('OpenAI request objects use the transport and upstream errors do not retry inference', async () => {
	for (const status of [200, 429, 503]) {
		const body =
			status === 200
				? {
						id: 'chat-1',
						object: 'chat.completion',
						model: request.model,
						choices: [
							{ index: 0, message: { role: 'assistant', content: 'Hello' }, finish_reason: 'stop' }
						]
					}
				: { error: { message: 'Unavailable', type: 'server_error' } };
		const state = await fixture(() =>
			response([
				record(4),
				record(4),
				record(1, JSON.stringify({ status, headers: { 'content-type': 'application/json' } })),
				record(2, JSON.stringify(body)),
				record(3)
			])
		);
		try {
			const phases = [];
			const result = state.client.chat.completions.create(request, {
				fetchOptions: { onProgress: (phase) => phases.push(phase) }
			});
			if (status === 200) assert.equal((await result).choices[0].message.content, 'Hello');
			else await assert.rejects(result, (error) => error.status === status);
			assert.deepEqual(phases, ['securing', 'encrypting', 'sending', 'acknowledged']);
			assert.equal(state.calls(), 1);
			const headers = JSON.parse(new TextDecoder().decode(state.exchanges[0].sealed[0].bytes));
			assert.equal(headers.headers.authorization, 'Bearer private-example-key');
			assert.equal(headers.path, '/v1/chat/completions');
			assert.deepEqual(
				JSON.parse(new TextDecoder().decode(state.exchanges[0].sealed[1].bytes)),
				request
			);
		} finally {
			await state.transport.close();
		}
	}
});

test('OpenAI DONE stays pending until record completion; a missing final record is an error', async () => {
	for (const valid of [true, false]) {
		let release;
		const gate = new Promise((resolve) => {
			release = resolve;
		});
		const content = {
			id: 'chat-1',
			object: 'chat.completion.chunk',
			model: request.model,
			choices: [{ index: 0, delta: { content: 'Hello' }, finish_reason: null }]
		};
		const state = await fixture(
			() =>
				new Response(
					new ReadableStream({
						async start(controller) {
							controller.enqueue(record(4));
							controller.enqueue(
								record(
									1,
									JSON.stringify({ status: 200, headers: { 'content-type': 'text/event-stream' } })
								)
							);
							controller.enqueue(
								record(
									2,
									`: STOGAS PROCESSING\n\ndata: ${JSON.stringify(content)}\n\ndata: [DONE]\n\n`
								)
							);
							await gate;
							if (valid) controller.enqueue(record(3));
							controller.close();
						}
					}),
					{ headers: { 'content-type': SESSION_CONTENT_TYPE } }
				)
		);
		try {
			const phases = [];
			const stream = await state.client.chat.completions.create(
				{ ...request, stream: true },
				{
					fetchOptions: { onProgress: (phase) => phases.push(phase) }
				}
			);
			assert.deepEqual(phases, ['securing', 'encrypting', 'sending', 'acknowledged']);
			const iterator = stream[Symbol.asyncIterator]();
			assert.equal((await iterator.next()).value.choices[0].delta.content, 'Hello');
			let finished = false;
			const terminal = iterator.next().finally(() => {
				finished = true;
			});
			await new Promise((resolve) => setImmediate(resolve));
			assert.equal(finished, false);
			release();
			if (valid) assert.equal((await terminal).done, true);
			else await assert.rejects(terminal, { submission: 'execution_unknown' });
			assert.equal(state.calls(), 1);
		} finally {
			release();
			await state.transport.close();
		}
	}
});
