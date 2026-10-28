import test from 'node:test';
import assert from 'node:assert/strict';

import { auth } from './helpers.js';
import { encodeBaaIntermediate, handleMfiSap, runMfiSapPeer } from '../src/sap.js';

test('MFI SAP exchange verifies the signature and carries the certificate', () => {
  const authenticator = auth();
  const result = runMfiSapPeer(authenticator);
  assert.equal(result.ok, true);
  assert.equal(result.baa, false);
  assert.equal(result.signature.length, 64);
  assert.equal(result.certificate.equals(authenticator.readCertificate()), true);
  assert.equal(result.accPublicKey.length, 32);
});

test('protocol major 2 uses SHA-1 over the two public keys', () => {
  const authenticator = auth({ protocolMajor: 2 });
  const result = runMfiSapPeer(authenticator);
  assert.equal(result.ok, true);
  assert.equal(authenticator.protocolMajor(), 2);
});

test('BAA SAP exchange verifies the signature and appends the baIC blob', () => {
  const authenticator = auth({ type: 'baa' });
  const result = runMfiSapPeer(authenticator);
  assert.equal(result.ok, true);
  assert.equal(result.baa, true);
  assert.equal(result.signature.length, 64);
});

test('malformed SAP requests return null', () => {
  const authenticator = auth();
  assert.equal(handleMfiSap(Buffer.alloc(32), authenticator), null);
  assert.equal(handleMfiSap(Buffer.alloc(34), authenticator), null);
  assert.equal(
    handleMfiSap(Buffer.concat([Buffer.from([2]), Buffer.alloc(32)]), authenticator),
    null,
  );
});

test('a zero shared secret is rejected', () => {
  const authenticator = auth();
  assert.equal(
    handleMfiSap(Buffer.concat([Buffer.from([1]), Buffer.alloc(32)]), authenticator),
    null,
  );
});

test('baIC OPACK headers follow the app encoding', () => {
  function header(length) {
    const encoded = encodeBaaIntermediate(Buffer.alloc(length, 0x11));
    return encoded.subarray(0, encoded.length - length).toString('hex');
  }
  assert.equal(header(0x20), 'e1446261494390');
  assert.equal(header(0x21), 'e144626149439121');
  assert.equal(header(0x100), 'e14462614943920001');
  assert.equal(header(0x10000), 'e144626149439300000100');
});
