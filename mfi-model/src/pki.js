/**
 * Test PKI and synthetic MFi authenticator.
 *
 * Everything here is generated test material. The model never reads the Apple/Carlinkit
 * identity shipped in the APK.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { signDigest, signRawDigest } from './ecdsa.js';
import { concat, u32 } from './bytes.js';

const GENERATOR = path.join(import.meta.dirname, '..', '..', 'tools', 'gen-test-pki.sh');

/**
 * Generate the test PKI once per directory. Generation happens in a sibling temporary
 * directory and is renamed into place, so concurrent test files cannot observe a partial PKI.
 */
export function ensureTestPki(directory) {
  const marker = path.join(directory, 'leaf.p7b');
  if (fs.existsSync(marker) && fs.existsSync(path.join(directory, 'ca.der'))) return directory;

  fs.mkdirSync(path.dirname(directory), { recursive: true });
  const temporary = `${directory}.tmp-${process.pid}-${Date.now()}`;
  try {
    execFileSync('bash', [GENERATOR, temporary], { stdio: 'pipe' });
    try {
      fs.renameSync(temporary, directory);
    } catch (error) {
      fs.rmSync(temporary, { recursive: true, force: true });
      if (!fs.existsSync(marker)) throw error;
    }
  } catch (error) {
    fs.rmSync(temporary, { recursive: true, force: true });
    const detail = error.stderr ? error.stderr.toString() : error.message;
    throw new Error(`failed to generate test PKI: ${detail}`);
  }
  return directory;
}

function read(directory, name) {
  return fs.readFileSync(path.join(directory, name));
}

export class TestMfiAuthenticator {
  constructor({
    privateKey,
    certificate,
    certificateType = 'mfi',
    protocolMajor = 3,
    leafDer,
    caDer,
    baaCertificates = null,
  }) {
    this.privateKey = privateKey;
    this.certificate = Buffer.from(certificate);
    this.certificateType = certificateType;
    this.major = protocolMajor;
    this.leafDer = Buffer.from(leafDer);
    this.caDer = Buffer.from(caDer);
    this.baaPair = baaCertificates;
  }

  protocolMajor() {
    return this.major;
  }

  readCertificate(maximumOutputLength = 65525) {
    if (this.certificate.length < 1 || this.certificate.length > maximumOutputLength) {
      throw new RangeError(
        `certificate length ${this.certificate.length} is outside 1..${maximumOutputLength}`,
      );
    }
    return Buffer.from(this.certificate);
  }

  /**
   * MFI: the input must be the 32-byte digest and is signed without re-hashing.
   * BAA: the app passes the 64-byte concatenation; the real chip's semantics are unknown, so
   * this model hashes a non-32-byte input with SHA-256 and records that as a modeled choice.
   */
  signChallenge(challenge) {
    const input = Buffer.from(challenge);
    if (this.certificateType === 'mfi') {
      if (input.length === 32) return signDigest(this.privateKey, input);
      if (input.length === 20 && this.major === 2) return signRawDigest(this.privateKey, input);
      throw new RangeError(
        `local MFi expects a 32-byte digest (or a 20-byte SHA-1 digest for major 2), got ${input.length}`,
      );
    }
    const digest = input.length === 32
      ? input
      : crypto.createHash('sha256').update(input).digest();
    return signDigest(this.privateKey, digest);
  }

  baaCertificates() {
    if (!this.baaPair) throw new Error('authenticator does not provide BAA certificates');
    return {
      leaf: Buffer.from(this.baaPair.leaf),
      intermediate: Buffer.from(this.baaPair.intermediate),
    };
  }

  publicKey() {
    return new crypto.X509Certificate(this.leafDer).publicKey;
  }
}

export function loadTestAuthenticator(directory, { type = 'mfi', protocolMajor = 3 } = {}) {
  ensureTestPki(directory);
  const caDer = read(directory, 'ca.der');

  if (type === 'baa') {
    const privateKey = crypto.createPrivateKey({
      key: read(directory, 'baa_leaf.pk8'),
      format: 'der',
      type: 'pkcs8',
    });
    const leaf = read(directory, 'baa_leaf.der');
    const intermediate = read(directory, 'int.der');
    const certificate = concat(u32(leaf.length), u32(intermediate.length), leaf, intermediate);
    if (!new crypto.X509Certificate(leaf).checkPrivateKey(privateKey)) {
      throw new Error('BAA test private key does not match its certificate');
    }
    return new TestMfiAuthenticator({
      privateKey,
      certificate,
      certificateType: 'baa',
      protocolMajor,
      leafDer: leaf,
      caDer,
      baaCertificates: { leaf, intermediate },
    });
  }

  const privateKey = crypto.createPrivateKey({
    key: read(directory, 'leaf.pk8'),
    format: 'der',
    type: 'pkcs8',
  });
  const leafDer = read(directory, 'leaf.der');
  const certificate = read(directory, 'leaf.p7b');
  if (!new crypto.X509Certificate(leafDer).checkPrivateKey(privateKey)) {
    throw new Error('test private key does not match its certificate');
  }
  return new TestMfiAuthenticator({
    privateKey,
    certificate,
    certificateType: 'mfi',
    protocolMajor,
    leafDer,
    caDer,
  });
}

/** Default shared PKI location used by the CLI and the pretest step. */
export function defaultPkiDirectory() {
  return path.join(import.meta.dirname, '..', 'build', 'test-pki');
}
