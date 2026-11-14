import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
	certificate_table_endorsements,
	crl_url,
	parse_report,
	vcek_url,
	verify,
	verify_crl
} from '../../packages/sev-snp/bindings/node/node.js';

const read = (path) => readFileSync(new URL(`../fixtures/sev-snp/${path}`, import.meta.url));
// 2026-11-14T00:00:00Z, when the fixtures' certificates and AMD's CRLs are valid.
const NOW = 1_794_614_400;
// The reports' REPORT_DATA is the bytes 00 to 3f.
const REPORT_DATA = Array.from({ length: 64 }, (_, index) =>
	index.toString(16).padStart(2, '0')
).join('');

const rejects = (code) => (error) => error.name === 'SevSnpError' && error.code === code;

test('a Google Cloud report verifies with its certificate table and AMD CRL', () => {
	const report = read('gcp-milan/report-vmpl0.bin');
	const endorsements = certificate_table_endorsements(read('gcp-milan/certificates.bin'), report);
	assert.deepEqual(Object.keys(endorsements), ['leaf', 'intermediate']);
	const policy = { report_data: REPORT_DATA, vmpl: 0, require_crl: true };
	const verified = verify(report, { ...endorsements, crl: read('amd-kds/milan.crl') }, policy, NOW);
	assert.equal(verified.product, 'Milan');
	assert.equal(verified.signing_key, 'vcek');
	assert.equal(verified.csp_id, undefined);
	assert.equal(verified.revocation_checked, true);
	assert.ok(verified.validity.not_before <= NOW && NOW <= verified.validity.not_after);
	assert.deepEqual(verified.report, parse_report(report));
	assert.throws(() => verify(report, endorsements, policy, NOW), rejects('missing_endorsement'));
	assert.throws(() => verify(report, endorsements, { vmpl: 1 }, NOW), rejects('policy'));
	// The CRL's validity is shorter than the certificates'.
	const { validity } = verify(report, endorsements, {}, NOW);
	assert.ok(validity.not_after > verified.validity.not_after);
	for (const time of [validity.not_before - 1, validity.not_after + 1])
		assert.throws(() => verify(report, endorsements, {}, time), rejects('expired'));
});

test('an AWS report verifies with its VLEK and the built-in ASVK', () => {
	const report = read('aws-milan/report-vmpl0.bin');
	const endorsements = certificate_table_endorsements(read('aws-milan/certificates.bin'), report);
	assert.deepEqual(Object.keys(endorsements), ['leaf']);
	const verified = verify(
		report,
		endorsements,
		{ signers: ['vlek'], csp_ids: ['CN=cc-us-east-2.amazonaws.com'] },
		NOW
	);
	assert.equal(verified.signing_key, 'vlek');
	assert.equal(verified.csp_id, 'CN=cc-us-east-2.amazonaws.com');
	assert.equal(verified.report.chip_id, '00'.repeat(64));
	assert.equal(verified.report.guest_policy, '0x0000000002030000');
	assert.deepEqual(verified.report.current_version, [1, 58, 3]);
	assert.deepEqual(verified.report.reported_tcb, {
		bootloader: 4,
		tee: 0,
		snp: 31,
		microcode: 225
	});
	assert.throws(() => vcek_url(report), rejects('binding'));
});

test('a changed report, certificate or argument fails with its code', () => {
	const report = read('gcp-milan/report-vmpl0.bin');
	const endorsements = certificate_table_endorsements(read('gcp-milan/certificates.bin'), report);
	const changed = Uint8Array.from(report);
	changed[0x90] ^= 1;
	assert.throws(() => verify(changed, endorsements, {}, NOW), rejects('signature'));
	assert.throws(() => verify(report.subarray(1), endorsements, {}, NOW), rejects('report'));
	const leaf = Uint8Array.from(endorsements.leaf);
	leaf[leaf.length - 1] ^= 1;
	assert.throws(() => verify(report, { leaf }, {}, NOW), rejects('signature'));
	// Another chip's VCEK.
	assert.throws(
		() => verify(report, { leaf: read('go-sev-guest/vcek.der') }, {}, NOW),
		rejects('binding')
	);
	// A misspelled requirement or endorsement fails instead of going unchecked.
	assert.throws(
		() => verify(report, endorsements, { measurement: '00'.repeat(48) }, NOW),
		rejects('invalid_policy')
	);
	assert.throws(
		() => verify(report, endorsements, { report_data: REPORT_DATA.toUpperCase() }, NOW),
		rejects('invalid_policy')
	);
	assert.throws(() => verify(report, endorsements, 'not a policy', NOW), rejects('invalid_policy'));
	assert.throws(
		() => verify(report, { ...endorsements, CRL: read('amd-kds/milan.crl') }, {}, NOW),
		TypeError
	);
	assert.throws(() => verify(report, { leaf: [...endorsements.leaf] }, {}, NOW), TypeError);
	assert.throws(() => verify(report, {}, {}, NOW), TypeError);
	for (const now of [-1, 1.5, Number.NaN, 2 ** 53])
		assert.throws(() => verify(report, endorsements, {}, now), TypeError);
	// Without a time, verification uses the current time.
	const verified = verify(report, endorsements, {});
	const current = Math.floor(Date.now() / 1000);
	assert.equal(
		verified.validity.not_before <= current && current <= verified.validity.not_after,
		true
	);
});

test('KDS URLs follow the report', () => {
	const report = read('gcp-milan/report-vmpl0.bin');
	const { chip_id, reported_tcb: tcb } = parse_report(report);
	const url = `https://kdsintf.amd.com/vcek/v1/Milan/${chip_id}?blSPL=${tcb.bootloader}&teeSPL=${tcb.tee}&snpSPL=${tcb.snp}&ucodeSPL=${tcb.microcode}`;
	assert.equal(vcek_url(report), url);
	assert.equal(vcek_url(report, 'Milan'), url);
	assert.throws(() => vcek_url(report, 'Genoa'), rejects('binding'));
	// A version 2 report does not name its product.
	const version2 = read('trustee/report.bin');
	assert.equal(parse_report(version2).product, null);
	assert.throws(() => vcek_url(version2), TypeError);
	assert.match(vcek_url(version2, 'Milan'), /^https:\/\/kdsintf\.amd\.com\/vcek\/v1\/Milan\//);
	assert.equal(crl_url('Turin'), 'https://kdsintf.amd.com/vcek/v1/Turin/crl');
	assert.throws(() => crl_url('Venice'), rejects('unsupported_product'));
});

test('a CRL names its product, number and revoked intermediates', () => {
	const genoa = verify_crl(read('amd-kds/genoa.crl'));
	assert.equal(genoa.product, 'Genoa');
	assert.deepEqual(genoa.revoked, ['020001']);
	assert.match(genoa.number, /^[0-9a-f]{40}$/);
	assert.ok(genoa.validity.not_before <= NOW && NOW <= genoa.validity.not_after);
	assert.deepEqual(verify_crl(read('amd-kds/milan.crl')).revoked, []);
	const changed = Uint8Array.from(read('amd-kds/genoa.crl'));
	changed[changed.length - 1] ^= 1;
	assert.throws(() => verify_crl(changed), rejects('signature'));
	// A Milan report with the Genoa CRL.
	const report = read('gcp-milan/report-vmpl0.bin');
	const endorsements = certificate_table_endorsements(read('gcp-milan/certificates.bin'), report);
	assert.throws(
		() => verify(report, { ...endorsements, crl: read('amd-kds/genoa.crl') }, {}, NOW),
		rejects('binding')
	);
});
