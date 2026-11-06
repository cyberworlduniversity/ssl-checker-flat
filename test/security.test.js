const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeHostname, isPublicAddress } = require('../server');

test('normalizes a hostname and a URL', () => {
  assert.equal(normalizeHostname('example.com'), 'example.com');
  assert.equal(normalizeHostname('https://Example.com/path'), 'example.com');
});

test('rejects malformed input and credential-bearing URLs', () => {
  assert.throws(() => normalizeHostname(''));
  assert.throws(() => normalizeHostname('https://user:pass@example.com'));
  assert.throws(() => normalizeHostname('not a valid hostname'));
});

test('rejects non-standard ports', () => {
  assert.throws(() => normalizeHostname('https://example.com:8443'));
});

test('blocks private, loopback, and link-local destinations', () => {
  for (const address of ['10.0.0.1', '127.0.0.1', '192.168.1.1', '169.254.169.254', '::1', 'fe80::1', 'fc00::1']) {
    assert.equal(isPublicAddress(address), false, address);
  }
});

test('allows a public IP address', () => {
  assert.equal(isPublicAddress('8.8.8.8'), true);
});
