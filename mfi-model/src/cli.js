#!/usr/bin/env node
/**
 * MockMFI CLI: serve the remote MFi model, run selftests, or print wire vectors.
 *
 * The model uses a freshly generated test PKI. It never reads or uses the Apple/Carlinkit
 * identity shipped in the APK.
 */

import crypto from 'node:crypto';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import {
  CoprocessorModel,
} from './coprocessor.js';
import { buildFrame, encodeFrame } from './csm.js';
import { derToRaw, rawToDer, verifyDigest } from './ecdsa.js';
import { AUTH, Iap2MfiResponder } from './iap2-auth.js';
import {
  createFramePair,
  hasAppleOid,
  hasTestOid,
  runIap2Session,
  runResponderLoop,
  runSapSession,
  verifyCertificate,
} from './mock-phone.js';
import { defaultPkiDirectory, loadTestAuthenticator } from './pki.js';
import { RemoteMfiClient } from './remote-client.js';
import {
  closeServer,
  createRemoteMfiServer,
  listen,
} from './remote-server.js';

const WORKSPACE = path.join(import.meta.dirname, '..', '..');

function fail(message) {
  throw new Error(message);
}

function check(condition, message) {
  if (!condition) fail(message);
}

function fakeAuthenticator(certificate, signature) {
  return {
    certificateType: 'mfi',
    protocolMajor: () => 3,
    readCertificate: () => Buffer.from(certificate),
    signChallenge: () => Buffer.from(signature),
  };
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith('--')) {
      args._.push(item);
      continue;
    }
    const key = item.slice(2);
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) {
      args[key] = true;
    } else {
      args[key] = next;
      index += 1;
    }
  }
  return args;
}

function load(overrides = {}) {
  const directory = overrides.pki ?? defaultPkiDirectory();
  const type = overrides.baa ? 'baa' : 'mfi';
  return { directory, authenticator: loadTestAuthenticator(directory, { type }) };
}

async function selftest() {
  const { directory, authenticator } = load();
  const caDer = authenticator.caDer;

  // 1. P-256 raw-digest signing.
  const digest = crypto.createHash('sha256').update('mockmfi selftest').digest();
  const signature = authenticator.signChallenge(digest);
  check(signature.length === 64, 'signature must be 64 bytes');
  check(verifyDigest(authenticator.publicKey(), digest, signature), 'signature must verify');
  const changed = Buffer.from(digest);
  changed[0] ^= 1;
  check(!verifyDigest(authenticator.publicKey(), changed, signature), 'changed digest must fail');
  check(derToRaw(rawToDer(signature)).equals(signature), 'DER/raw round-trip must hold');
  console.log(`PASS ecdsa rawDigest=32 signature=64 protocolMajor=${authenticator.protocolMajor()}`);

  // 2. CSM vectors.
  const certFrame = buildFrame(AUTH.CERTIFICATE, [{ id: 0, payload: Buffer.from('ABC') }]);
  check(certFrame.toString('hex') === '4040000daa0100070000414243', 'certificate frame vector');
  check(encodeFrame(AUTH.REQUEST_CERTIFICATE).toString('hex') === '40400006aa00', 'request frame vector');
  console.log('PASS csm frame=0x4040 header=6');

  // 3. Coprocessor register model, including 128-byte certificate windows.
  const certificate = Buffer.alloc(300, 0x5a);
  const fakeSignature = Buffer.from(Array.from({ length: 128 }, (_, index) => (0xa0 + index) & 0xff));
  const coprocessor = new CoprocessorModel({ authenticator: fakeAuthenticator(certificate, fakeSignature) });
  const select = (register) => coprocessor.transaction(0x10, Buffer.from([register]), 0);
  const read = (count) => coprocessor.transaction(0x10, Buffer.alloc(0), count);

  select(0x30);
  check(read(2).readUInt16BE(0) === 300, 'certificate length');
  const windows = [];
  for (const [register, count] of [[0x31, 128], [0x32, 128], [0x33, 44]]) {
    select(register);
    windows.push(read(count));
  }
  check(Buffer.concat(windows).equals(certificate), 'certificate windows must reproduce the certificate');

  const challenge = Buffer.alloc(20, 0x11);
  check(
    coprocessor.transaction(0x10, Buffer.concat([Buffer.from([0x20]), Buffer.from([0x00, 0x14])]), 0).length === 0,
    'challenge length write',
  );
  check(
    coprocessor.transaction(0x10, Buffer.concat([Buffer.from([0x21]), challenge]), 0).length === 0,
    'challenge write',
  );
  check(
    coprocessor.transaction(0x10, Buffer.from([0x10, 0x01]), 0).length === 0,
    'auth start write',
  );
  select(0x10);
  check(read(1)[0] === 0x10, 'auth success status');
  select(0x11);
  const length = read(2).readUInt16BE(0);
  select(0x12);
  const signed = read(length);
  check(signed.equals(fakeSignature), 'coprocessor signature bytes');
  console.log('PASS coprocessor windows=128 challenge=20 signature=128');

  // 4. iAP2 AccAuthentication.
  const { phone, accessory } = createFramePair();
  const responder = new Iap2MfiResponder(authenticator);
  const loop = runResponderLoop(accessory, responder);
  const session = await runIap2Session(phone, authenticator, caDer);
  await loop;
  check(session.certificateCheck.ok, `certificate check failed: ${session.certificateCheck.reason}`);
  check(session.verified, 'iAP2 signature must verify');
  check(hasTestOid(authenticator.leafDer), 'test OID must be present');
  check(!hasAppleOid(authenticator.leafDer), 'Apple OID must be absent');
  console.log('PASS iap2 0xAA00-0xAA05 signature=64');

  // 5. AirPlay MFiSAP.
  const sap = runSapSession(authenticator);
  check(sap.ok, 'SAP signature must verify');
  check(sap.certificate.length > 0, 'SAP certificate must be present');
  console.log('PASS sap x25519=ok aes-ctr=ok signature=64');

  // 6. Remote contract.
  const server = createRemoteMfiServer({ authenticator, host: '127.0.0.1' });
  const listening = await listen(server, { host: '127.0.0.1', port: 0 });
  try {
    const client = new RemoteMfiClient(listening.url, { token: null });
    await client.reset();
    check((await client.protocolMajor()) === 3, 'remote protocol major');
    const remoteCertificate = await client.readCertificate();
    check(remoteCertificate.length === authenticator.readCertificate().length, 'remote certificate length');
    const remoteSignature = await client.signChallenge(digest);
    check(verifyDigest(authenticator.publicKey(), digest, remoteSignature), 'remote signature must verify');
    console.log(`PASS remote url=${listening.url} endpoints=3`);
  } finally {
    await closeServer(server);
  }

  console.log(`PASS selftest pki=${directory}`);
}

function printVectors() {
  const certificate = encodeFrame(AUTH.REQUEST_CERTIFICATE);
  const withCertificate = buildFrame(AUTH.CERTIFICATE, [{ id: 0, payload: Buffer.from('ABC') }]);
  const challenge = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  const challengeFrame = buildFrame(AUTH.REQUEST_CHALLENGE, [{ id: 0, payload: challenge }]);
  const signature = Buffer.from(Array.from({ length: 64 }, (_, index) => 0x80 + index));
  const signatureFrame = buildFrame(AUTH.RESPONSE, [{ id: 0, payload: signature }]);
  console.log(`aa00  ${certificate.toString('hex')}`);
  console.log(`aa01  ${withCertificate.toString('hex')}`);
  console.log(`aa02  ${challengeFrame.toString('hex')}`);
  console.log(`aa03  ${signatureFrame.toString('hex')}`);
  console.log(`aa05  ${encodeFrame(AUTH.SUCCEEDED).toString('hex')}`);
}

async function iap2Selftest() {
  const { authenticator } = load();
  const { phone, accessory } = createFramePair();
  const loop = runResponderLoop(accessory, new Iap2MfiResponder(authenticator));
  const session = await runIap2Session(phone, authenticator, authenticator.caDer);
  await loop;
  check(session.certificateCheck.ok, session.certificateCheck.reason);
  check(session.verified, 'signature must verify');
  console.log(`PASS iap2 certificate=${session.certificate.length} signature=64`);
}

function sapSelftest() {
  const { authenticator } = load();
  const result = runSapSession(authenticator);
  check(result.ok, 'SAP signature must verify');
  console.log(`PASS sap certificate=${result.certificate.length} signature=${result.signature.length}`);
}

async function serve(args) {
  const { directory, authenticator } = load({
    pki: typeof args.pki === 'string' ? args.pki : undefined,
    baa: Boolean(args.baa),
  });
  const host = typeof args.host === 'string' ? args.host : '127.0.0.1';
  const port = Number(args.port ?? 8787);
  const token = typeof args.token === 'string' ? args.token : null;
  const delay = Number(args.delay ?? 0);

  const server = createRemoteMfiServer({
    authenticator,
    token,
    signDelayMs: delay,
    host,
    port,
  });
  const listening = await listen(server, { host, port });
  console.log(`MockMFI test service: ${listening.url}`);
  console.log(`  type=${authenticator.certificateType} protocolMajor=${authenticator.protocolMajor()} pki=${directory}`);
  console.log('  routes: GET /mfi/certificate  POST /mfi/sign  POST /mfi/reset');
  console.log('  test credentials only; this service does not authenticate to a real iPhone.');

  const shutdown = () => {
    closeServer(server).finally(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

function analyzeApk(args) {
  const apk = typeof args.apk === 'string'
    ? args.apk
    : path.join(WORKSPACE, 'DiPlay-0.2.22.apk');
  const script = path.join(WORKSPACE, 'tools', 'analyze-apk-identity.sh');
  const result = spawnSync('bash', [script, apk], { stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function help() {
  console.log(`Usage: node src/cli.js <command> [options]

Commands:
  serve              Run the remote MFi test service
    --port <n>       Port (default 8787)
    --host <addr>    Bind address (default 127.0.0.1)
    --token <text>   Require Authorization: Bearer <text>
    --baa            Serve the BAA test identity
    --pki <dir>      Test PKI directory (default mfi-model/build/test-pki)
    --delay <ms>     Delay the first sign request (retry test)
  selftest           Run all in-memory checks
  vectors            Print iAP2 wire vectors
  iap2-selftest      Run only the iAP2 exchange
  sap-selftest       Run only the AirPlay SAP exchange
  analyze-apk        Profile the APK's public MFi certificate (no key output)
    --apk <path>     APK path (default ../DiPlay-0.2.22.apk)
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0] ?? 'help';
  switch (command) {
    case 'serve':
      await serve(args);
      break;
    case 'selftest':
      await selftest();
      break;
    case 'vectors':
      printVectors();
      break;
    case 'iap2-selftest':
      await iap2Selftest();
      break;
    case 'sap-selftest':
      sapSelftest();
      break;
    case 'analyze-apk':
      analyzeApk(args);
      break;
    case 'help':
    default:
      help();
      break;
  }
}

main().catch((error) => {
  console.error(`FAIL ${error.stack ?? error.message}`);
  process.exit(1);
});
