import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  P256_ORDER,
  derToRaw,
  generateP256,
  isValidScalarPair,
  rawToDer,
  signDigest,
  signRawDigest,
  verifyDigest,
  verifyRawDigest,
} from '../src/ecdsa.js';

function digest(label) {
  return crypto.createHash('sha256').update(label).digest();
}

test('raw-digest sign and verify', () => {
  const { privateKey, publicKey } = generateP256();
  const value = digest('raw-digest');
  const signature = signDigest(privateKey, value);

  assert.equal(signature.length, 64);
  assert.equal(verifyDigest(publicKey, value, signature), true);
  assert.equal(isValidScalarPair(signature), true);

  const changed = Buffer.from(value);
  changed[0] ^= 1;
  assert.equal(verifyDigest(publicKey, changed, signature), false);

  const other = generateP256();
  assert.equal(verifyDigest(other.publicKey, value, signature), false);
});

test('rejects non-32-byte digests', () => {
  const { privateKey } = generateP256();
  for (const length of [0, 20, 31, 33, 64]) {
    assert.throws(() => signDigest(privateKey, Buffer.alloc(length)), /32-byte digest/);
  }
});

test('verify rejects malformed signatures without throwing', () => {
  const { publicKey } = generateP256();
  const value = digest('malformed');
  assert.equal(verifyDigest(publicKey, value, Buffer.alloc(63)), false);
  assert.equal(verifyDigest(publicKey, value, Buffer.alloc(65)), false);
  assert.equal(verifyDigest(publicKey, Buffer.alloc(31), Buffer.alloc(64)), false);
});

test('20-byte SHA-1 digest signs through the raw variant', () => {
  const { privateKey, publicKey } = generateP256();
  const value = crypto.createHash('sha1').update('major2').digest();
  const signature = signRawDigest(privateKey, value);
  assert.equal(signature.length, 64);
  assert.equal(verifyRawDigest(publicKey, value, signature), true);
  assert.equal(verifyDigest(publicKey, value, signature), false);
  assert.throws(() => signRawDigest(privateKey, Buffer.alloc(33)), /1\.\.32-byte/);
});

test('DER and raw round-trip', () => {
  const { privateKey } = generateP256();
  for (let index = 0; index < 8; index += 1) {
    const signature = signDigest(privateKey, digest(`round-trip-${index}`));
    assert.equal(derToRaw(rawToDer(signature)).equals(signature), true);
  }
});

test('DER rejects a negative integer', () => {
  assert.throws(
    () => derToRaw(Buffer.from('30060201010201ff', 'hex')),
    /negative ECDSA integer/,
  );
});

test('DER strips sign padding and pads to 32 bytes', () => {
  const raw = derToRaw(Buffer.from('30080203008001020101', 'hex'));
  assert.equal(raw.subarray(0, 30).toString('hex'), '00'.repeat(30));
  assert.equal(raw.subarray(30, 32).toString('hex'), '8001');
  assert.equal(raw.subarray(32).toString('hex'), `${'00'.repeat(31)}01`);
});

test('DER rejects wrong shapes', () => {
  assert.throws(() => derToRaw(Buffer.from('020101', 'hex')), /SEQUENCE/);
  assert.throws(() => derToRaw(Buffer.from('3006020101020101ff', 'hex')), /trailing|length/);
  assert.throws(() => derToRaw(Buffer.from('30060201010101', 'hex')), /INTEGER|truncated/);
});

test('rawToDer rejects a wrong length', () => {
  assert.throws(() => rawToDer(Buffer.alloc(63)), /64-byte/);
});

test('P-256 order sanity', () => {
  assert.equal(P256_ORDER > 0n, true);
  assert.equal((P256_ORDER & 1n) === 1n, true);
});
