import test from 'node:test';
import assert from 'node:assert/strict';

import { auth, withTimeout } from './helpers.js';
import { buildFrame, encodeParam, parseParams } from '../src/csm.js';
import {
  AUTH,
  Iap2MfiResponder,
  certificateFrame,
  certificateFrom,
  responseFrame,
  signatureFrom,
} from '../src/iap2-auth.js';
import { verifyDigest } from '../src/ecdsa.js';
import { createFramePair, runIap2Session, runResponderLoop } from '../src/mock-phone.js';

test('MFI certificate frame carries the exact certificate bytes', () => {
  const authenticator = auth();
  const frame = certificateFrame(authenticator);
  assert.equal(frame.readUInt16BE(4), AUTH.CERTIFICATE);
  const params = parseParams(frame.subarray(6));
  assert.equal(params.length, 1);
  assert.equal(params[0].id, 0);
  assert.equal(params[0].payload.equals(authenticator.readCertificate()), true);
});

test('BAA certificate frame carries leaf, marker, and intermediate', () => {
  const authenticator = auth({ type: 'baa' });
  const frame = certificateFrame(authenticator);
  const params = parseParams(frame.subarray(6));
  const pair = authenticator.baaCertificates();
  assert.equal(params.length, 3);
  assert.equal(params[0].payload.equals(pair.leaf), true);
  assert.equal(params[1].payload.equals(Buffer.from([1])), true);
  assert.equal(params[2].payload.equals(pair.intermediate), true);
});

test('responder handles request-certificate', () => {
  const authenticator = auth();
  const responder = new Iap2MfiResponder(authenticator);
  const reply = responder.handle({ messageId: AUTH.REQUEST_CERTIFICATE, payload: Buffer.alloc(0) });
  assert.equal(certificateFrom({ messageId: AUTH.CERTIFICATE, payload: reply.subarray(6) }).length, authenticator.readCertificate().length);
});

test('responder signs a 32-byte challenge', () => {
  const authenticator = auth();
  const responder = new Iap2MfiResponder(authenticator);
  const challenge = Buffer.alloc(32, 0x33);
  const reply = responder.handle({
    messageId: AUTH.REQUEST_CHALLENGE,
    payload: encodeParam(0, challenge),
  });
  const signature = signatureFrom({ messageId: AUTH.RESPONSE, payload: reply.subarray(6) });
  assert.equal(signature.length, 64);
  assert.equal(verifyDigest(authenticator.publicKey(), challenge, signature), true);
});

test('responder treats success as completion and failure as an error', () => {
  const responder = new Iap2MfiResponder(auth());
  assert.equal(responder.handle({ messageId: AUTH.SUCCEEDED, payload: Buffer.alloc(0) }), null);
  assert.throws(
    () => responder.handle({ messageId: AUTH.FAILED, payload: Buffer.alloc(0) }),
    /AuthenticationFailed/,
  );
  assert.throws(
    () => responder.handle({ messageId: 0xaa10, payload: Buffer.alloc(0) }),
    /unexpected/,
  );
});

test('responder rejects challenge lengths outside 1..128', () => {
  const responder = new Iap2MfiResponder(auth());
  for (const length of [0, 129]) {
    assert.throws(
      () => responder.handle({
        messageId: AUTH.REQUEST_CHALLENGE,
        payload: encodeParam(0, Buffer.alloc(length, 1)),
      }),
      /challenge length/,
    );
  }
});

test('responder rejects a challenge without parameter 0', () => {
  const responder = new Iap2MfiResponder(auth());
  assert.throws(
    () => responder.handle({ messageId: AUTH.REQUEST_CHALLENGE, payload: Buffer.alloc(0) }),
    /missing/,
  );
});

test('full iAP2 exchange verifies certificate and signature', async () => {
  const authenticator = auth();
  const { phone, accessory } = createFramePair();
  const loop = runResponderLoop(accessory, new Iap2MfiResponder(authenticator));
  const session = await withTimeout(
    runIap2Session(phone, authenticator, authenticator.caDer),
    3000,
    'iAP2 session',
  );
  await withTimeout(loop, 3000, 'responder loop');
  assert.equal(session.certificateCheck.ok, true, session.certificateCheck.reason);
  assert.equal(session.verified, true);
  assert.equal(session.signature.length, 64);
});

test('response frame shape', () => {
  const signature = Buffer.alloc(64, 0x80);
  const frame = responseFrame(signature);
  assert.equal(frame.readUInt16BE(4), AUTH.RESPONSE);
  assert.equal(signatureFrom({ messageId: AUTH.RESPONSE, payload: frame.subarray(6) }).equals(signature), true);
  assert.equal(
    buildFrame(0xaa02, [{ id: 0, payload: Buffer.alloc(32) }]).readUInt16BE(2),
    42,
  );
});
