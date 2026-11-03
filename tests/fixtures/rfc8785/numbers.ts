// Writes numbers.json: doubles with the text that ECMAScript's Number.prototype.toString gives
// them, which RFC 8785 section 3.2.2.3 requires. Run with `bun tests/fixtures/rfc8785/numbers.ts`.
// The generator is seeded, so the file is the same on every run.
const view = new DataView(new ArrayBuffer(8));
let state = 0x9e3779b97f4a7c15n;
const next = () => {
	// xorshift64*
	state ^= state >> 12n;
	state ^= (state << 25n) & 0xffffffffffffffffn;
	state ^= state >> 27n;
	return (state * 0x2545f4914f6cdd1dn) & 0xffffffffffffffffn;
};
const cases: [string, string][] = [];
const add = (bits: bigint) => {
	view.setBigUint64(0, bits);
	const value = view.getFloat64(0);
	if (Number.isFinite(value)) cases.push([bits.toString(16).padStart(16, '0'), String(value)]);
};
// Boundaries where the notation changes, and integers around 2^53.
for (const value of [1e21, 1e-7, 1e-6, 9007199254740991, 9007199254740992, 2 ** 63, 5e-324, 2.2250738585072014e-308]) {
	view.setFloat64(0, value);
	const bits = view.getBigUint64(0);
	for (let delta = -3n; delta <= 3n; delta++) add(bits + delta);
}
for (let exponent = -1074; exponent <= 1023; exponent += 7) {
	view.setFloat64(0, 2 ** exponent);
	add(view.getBigUint64(0));
}
// Random bit patterns cover every exponent; random integers and short decimals cover the
// values that requests and responses carry.
for (let index = 0; index < 2500; index++) add(next());
for (let index = 0; index < 500; index++) {
	view.setFloat64(0, Number(next() % 10000000000000n) / 10 ** Number(next() % 12n));
	add(view.getBigUint64(0));
}
const lines = cases.map((pair) => `\t${JSON.stringify(pair)}`).join(',\n');
await Bun.write(new URL('numbers.json', import.meta.url), `[\n${lines}\n]\n`);
console.log(`${cases.length} numbers`);
