import { StogasTransport } from '../../bindings/worker/worker.js';
import { checkLiveGateway } from '../browser/live.mjs';

export default {
	async fetch(request) {
		try {
			await checkLiveGateway(StogasTransport, new URL(request.url).searchParams.get('environment'));
			return new Response('passed');
		} catch (error) {
			return new Response(String(error?.stack ?? error), { status: 500 });
		}
	}
};
