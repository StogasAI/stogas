import { test } from 'node:test';
import { StogasTransport } from 'stogas';
import { checkLiveGateway } from '../browser/live.mjs';

const environment = process.env.STOGAS_LIVE;

// STOGAS_LIVE=staging|prod uses the network; every other test here stays offline.
test('live gateway rejects an invalid key through E2EE', { skip: !environment }, () =>
	checkLiveGateway(StogasTransport, environment)
);
