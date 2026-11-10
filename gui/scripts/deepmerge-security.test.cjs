const { test } = require('node:test');
const assert = require('node:assert/strict');
const merge = require('deepmerge');
for (const key of ['__proto__', 'constructor', 'prototype']) {
  for (const side of ['source', 'target']) {
    test(`${key} blocked on ${side}, including null prototypes`, () => {
      const hostile = Object.create(null);
      hostile[key] = { poisoned: true };
      hostile.safe = { nested: [1] };
      const out = side === 'source' ? merge({}, hostile) : merge(hostile, {});
      assert.equal(Object.getPrototypeOf(out), Object.prototype);
      assert.equal(Object.hasOwn(out, key), false);
      assert.equal(out.poisoned, undefined);
      assert.deepEqual(out.safe, { nested: [1] });
    });
  }
}
test('nested JSON payloads and normal config merging', () => {
  const hostile = JSON.parse('{"nested":{"__proto__":{"poisoned":true}},"list":[2]}');
  const out = merge({ nested: { safe: true }, list: [1] }, hostile);
  assert.deepEqual(out, { nested: { safe: true }, list: [1, 2] });
  assert.equal({}.poisoned, undefined);
});
test('customMerge never receives dangerous keys', () => {
  const hostile = JSON.parse('{"__proto__":{"poisoned":true},"safe":{"b":2}}');
  const out = merge({safe: {a: 1}}, hostile, { customMerge(key) {
    assert.notEqual(key, '__proto__');
  }});
  assert.deepEqual(out.safe, {a: 1, b: 2});
});

test('Svelte build plugin resolves the reviewed patched implementation', () => {
  const { createRequire } = require('node:module');
  const pluginRequire = createRequire(require.resolve('@sveltejs/vite-plugin-svelte'));
  assert.equal(pluginRequire.resolve('deepmerge'), require.resolve('deepmerge'));
  assert.equal(pluginRequire('deepmerge'), merge);
});
