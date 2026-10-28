import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { auth } from './helpers.js';
import { hasAppleOid, hasTestOid, verifyCertificate, verifyChain } from '../src/mock-phone.js';
import { ensureTestPki } from '../src/pki.js';

const APK = path.join(import.meta.dirname, '..', '..', 'DiPlay-0.2.22.apk');

test('the synthetic identity carries only the test OID', () => {
  const authenticator = auth();
  assert.equal(hasTestOid(authenticator.leafDer), true);
  assert.equal(hasAppleOid(authenticator.leafDer), false);
});

test('the synthetic certificate verifies against its own test CA', () => {
  const authenticator = auth();
  assert.equal(verifyCertificate(authenticator.leafDer, authenticator.caDer).ok, true);
});

test('the synthetic certificate fails against an unrelated CA', () => {
  const authenticator = auth();
  const other = path.join(os.tmpdir(), `mockmfi-unrelated-${process.pid}`);
  ensureTestPki(other);
  const otherCa = fs.readFileSync(path.join(other, 'ca.der'));
  const result = verifyCertificate(authenticator.leafDer, otherCa);
  assert.equal(result.ok, false);
  assert.match(result.reason, /not issued|does not verify/);
});

test('the BAA leaf does not verify directly against the root', () => {
  const authenticator = auth({ type: 'baa' });
  const pair = authenticator.baaCertificates();
  assert.equal(verifyChain(pair.leaf, pair.intermediate, authenticator.caDer).ok, true);
  assert.equal(verifyCertificate(pair.leaf, authenticator.caDer).ok, false);
});

test(
  'the shipped Apple certificate carries the Apple marker (detection check only)',
  { skip: !fs.existsSync(APK) },
  () => {
    const p7b = execFileSync('unzip', ['-p', APK, 'assets/offline-mfi/certificate.p7b']);
    const pem = execFileSync('openssl', ['pkcs7', '-inform', 'DER', '-print_certs'], {
      input: p7b,
    });
    const der = execFileSync('openssl', ['x509', '-outform', 'DER'], { input: pem });
    assert.equal(hasAppleOid(der), true);
    assert.equal(hasTestOid(der), false);
  },
);
