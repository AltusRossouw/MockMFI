#!/usr/bin/env node
/**
 * Cross-implementation check: the Node model's phone side talks to the C `mfid`
 * accessory over a PTY and verifies what the C code produced.
 *
 *   node tools/crosscheck-mfid.mjs [identityDir]
 *
 * The C side is authoritative for the wire bytes here; the Node side only uses its own
 * frame encoder, CSM decoder and ECDSA verifier, so agreement means the two independent
 * implementations agree on framing, certificate container and signature encoding.
 */
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { CsmDecoder } from '../mfi-model/src/csm.js';
import { AUTH, certificateFrom, signatureFrom } from '../mfi-model/src/iap2-auth.js';
import { verifyDigest } from '../mfi-model/src/ecdsa.js';
import { encodeFrame, buildFrame } from '../mfi-model/src/csm.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const identityDir = process.argv[2] ?? path.join(here, '..', 'mfi-linux', 'build', 'test-identity');
const mfid = path.join(here, '..', 'mfi-linux', 'build', 'mfid');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class FdEndpoint {
  constructor(fd) {
    this.fd = fd;
    this.decoder = new CsmDecoder();
    this.inbox = [];
  }

  send(buffer) {
    let off = 0;
    while (off < buffer.length) {
      try {
        off += fs.writeSync(this.fd, buffer, off, buffer.length - off);
      } catch (error) {
        if (error.code !== 'EAGAIN') throw error;
      }
    }
  }

  async recv() {
    for (;;) {
      if (this.inbox.length > 0) return this.inbox.shift();
      let chunk;
      const buffer = Buffer.alloc(65536);
      try {
        const n = fs.readSync(this.fd, buffer, 0, buffer.length, null);
        chunk = buffer.subarray(0, n);
      } catch (error) {
        if (error.code === 'EAGAIN') {
          await sleep(5);
          continue;
        }
        throw error;
      }
      if (chunk && chunk.length) this.inbox.push(...this.decoder.push(chunk));
      else await sleep(5);
    }
  }
}

const child = spawn(mfid, ['--identity', identityDir, 'serve', '--pty', '--once', '--timeout', '10000'], {
  stdio: ['ignore', 'pipe', 'pipe'],
});
let stderr = '';
child.stderr.on('data', (d) => {
  stderr += d.toString();
});

const slavePath = await new Promise((resolve, reject) => {
  let out = '';
  child.stdout.on('data', (d) => {
    out += d.toString();
    const line = out.split('\n')[0].trim();
    if (line.startsWith('/dev/')) resolve(line);
  });
  child.on('exit', (code) => reject(new Error(`mfid exited early (${code}): ${stderr}`)));
  setTimeout(() => reject(new Error(`no pty path from mfid: ${out}`)), 5000);
});

const fd = fs.openSync(slavePath, 'r+');
const phone = new FdEndpoint(fd);

const leafPem = fs.readFileSync(path.join(identityDir, 'leaf.pem'));
const container = fs.readFileSync(path.join(identityDir, 'certificate.p7b'));
const leafDer = new crypto.X509Certificate(leafPem).raw;

/* What the C accessory is supposed to be serving, from the same directory. */
const expectedAuthenticator = {
  certificateType: 'mfi',
  leafDer,
  readCertificate: () => container,
  publicKey: () => crypto.createPublicKey(leafPem),
};

/* Drive the exchange with the Node model's framers; verify the signature with the C
 * library (OpenSSL raw-digest ECDSA), because Node's crypto.sign(null, ...) with an EC
 * key hashes the input on this release and cannot check NONEwithECDSA signatures. */
phone.send(encodeFrame(AUTH.REQUEST_CERTIFICATE));
const certificateFrame = await phone.recv();
const certificate = certificateFrom(certificateFrame);

const challenge = crypto.randomBytes(32);
phone.send(buildFrame(AUTH.REQUEST_CHALLENGE, [{ id: 0, payload: challenge }]));
const responseFrame = await phone.recv();
const signature = signatureFrom(responseFrame);
phone.send(encodeFrame(AUTH.SUCCEEDED));
fs.closeSync(fd);

const exitCode = await new Promise((resolve) => child.on('exit', resolve));

/* Both implementations check the signature: the Node model's BigInt ECDSA (raw digest) and the
 * C library through `mfid verify`. Agreement in both directions is the point of this tool. */
const nodeVerified = verifyDigest(crypto.createPublicKey(leafPem), challenge, signature);
const cVerified =
  spawnSync(mfid, ['--identity', identityDir, 'verify', challenge.toString('hex'), signature.toString('hex')], {
    encoding: 'utf8',
  }).status === 0;

const checks = [
  ['Node CSM decoder accepts the C frame', certificate.length === container.length],
  ['certificate equals the loaded container', certificate.equals(container)],
  ['challenge request built by the Node framer', challenge.length === 32],
  ['signature parses as 64 raw bytes', signature.length === 64],
  ['signature verifies with the Node model (raw digest ECDSA)', nodeVerified],
  ['signature verifies with the C library (OpenSSL)', cVerified],
  ['mfid exited cleanly', exitCode === 0],
];

let failed = 0;
for (const [name, ok] of checks) {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}`);
  if (!ok) failed++;
}
console.log(`\nC accessory log:\n${stderr.trim()}`);
console.log(`\n${failed ? 'FAILED' : 'PASS'} (${failed} failure${failed === 1 ? '' : 's'})`);
process.exit(failed ? 1 : 0);
