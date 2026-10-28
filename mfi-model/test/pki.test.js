import test from 'node:test';
import assert from 'node:assert/strict';

import { auth } from './helpers.js';
import { hasAppleOid, hasTestOid, verifyCertificate, verifyChain } from '../src/mock-phone.js';

test('MFI test identity loads and signs', () => {
  const authenticator = auth();
  assert.equal(authenticator.protocolMajor(), 3);
  assert.equal(authenticator.certificateType, 'mfi');
  assert.ok(authenticator.readCertificate().length > 0);
  assert.throws(() => authenticator.readCertificate(1), /outside/);
  assert.throws(() => authenticator.signChallenge(Buffer.alloc(16)), /32-byte digest/);

  const signature = authenticator.signChallenge(Buffer.alloc(32, 1));
  assert.equal(signature.length, 64);
});

test('MFI certificate verifies against the test CA and carries the test OID', () => {
  const authenticator = auth();
  const check = verifyCertificate(authenticator.leafDer, authenticator.caDer);
  assert.equal(check.ok, true, check.reason);
  assert.equal(hasTestOid(authenticator.leafDer), true);
  assert.equal(hasAppleOid(authenticator.leafDer), false);
});

test('BAA test identity packages leaf and intermediate', () => {
  const authenticator = auth({ type: 'baa' });
  assert.equal(authenticator.certificateType, 'baa');
  const certificate = authenticator.readCertificate();
  const leafLength = certificate.readUInt32BE(0);
  const intermediateLength = certificate.readUInt32BE(4);
  assert.equal(8 + leafLength + intermediateLength, certificate.length);

  const pair = authenticator.baaCertificates();
  assert.equal(pair.leaf.length, leafLength);
  assert.equal(pair.intermediate.length, intermediateLength);
  assert.equal(verifyChain(pair.leaf, pair.intermediate, authenticator.caDer).ok, true);
  assert.equal(hasTestOid(pair.leaf, 'baa'), true);
  assert.equal(hasAppleOid(pair.leaf), false);
});

test('protocol major is configurable for the SHA-1 SAP path', () => {
  const authenticator = auth({ protocolMajor: 2 });
  assert.equal(authenticator.protocolMajor(), 2);
});

test('certificate and key are load-time checked', () => {
  const authenticator = auth();
  // The loader already verifies checkPrivateKey; a successful load is the assertion.
  assert.ok(authenticator.privateKey);
  assert.ok(authenticator.publicKey());
});
