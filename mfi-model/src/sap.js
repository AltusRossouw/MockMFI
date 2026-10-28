/**
 * AirPlay `/auth-setup` MFiSAP responder and a matching peer driver.
 *
 * Mirrors `MfiSapAuthSetup.kt`: X25519, SHA-1-derived AES-128-CTR key/IV, SHA-256 (or SHA-1
 * for protocol major 2) over the two public keys, and the exact response layout.
 */

import crypto from 'node:crypto';

import { concat } from './bytes.js';
import { verifyDigest, verifyRawDigest } from './ecdsa.js';

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export function rawX25519PublicKey(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  if (der.length !== 44 || !der.subarray(0, 12).equals(X25519_SPKI_PREFIX)) {
    throw new Error('unexpected X25519 SubjectPublicKeyInfo layout');
  }
  return Buffer.from(der.subarray(12));
}

export function x25519PublicKeyFromRaw(raw) {
  if (!Buffer.isBuffer(raw) || raw.length !== 32) {
    throw new RangeError('X25519 public key must be 32 bytes');
  }
  return crypto.createPublicKey({
    key: concat(X25519_SPKI_PREFIX, raw),
    format: 'der',
    type: 'spki',
  });
}

export function x25519Generate() {
  const pair = crypto.generateKeyPairSync('x25519');
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    rawPublicKey: rawX25519PublicKey(pair.publicKey),
  };
}

export function x25519Shared(privateKey, peerPublicKeyRaw) {
  return crypto.diffieHellman({
    privateKey,
    publicKey: x25519PublicKeyFromRaw(peerPublicKeyRaw),
  });
}

function digest(algorithm, ...parts) {
  const hash = crypto.createHash(algorithm);
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function sha1(...parts) {
  return digest('sha1', ...parts);
}

function sha256(...parts) {
  return digest('sha256', ...parts);
}

export function aesCtr128(key, iv, data) {
  const cipher = crypto.createCipheriv('aes-128-ctr', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function keySchedule(shared) {
  return {
    aesKey: sha1(Buffer.from('AES-KEY'), shared).subarray(0, 16),
    aesIv: sha1(Buffer.from('AES-IV'), shared).subarray(0, 16),
  };
}

export function encodeBaaIntermediate(intermediate) {
  const value = Buffer.from(intermediate);
  const key = Buffer.from([0xe1, 0x44, 0x62, 0x61, 0x49, 0x43]);
  let header;
  if (value.length <= 0x20) {
    header = Buffer.concat([key, Buffer.from([0x70 + value.length])]);
  } else if (value.length <= 0xff) {
    header = Buffer.concat([key, Buffer.from([0x91, value.length])]);
  } else if (value.length <= 0xffff) {
    header = Buffer.concat([key, Buffer.from([0x92, value.length & 0xff, (value.length >>> 8) & 0xff])]);
  } else {
    header = Buffer.concat([
      key,
      Buffer.from([
        0x93,
        value.length & 0xff,
        (value.length >>> 8) & 0xff,
        (value.length >>> 16) & 0xff,
        (value.length >>> 24) & 0xff,
      ]),
    ]);
  }
  return Buffer.concat([header, value]);
}

function buildMfiResponse(publicKey, certificate, encryptedSignature) {
  const response = Buffer.alloc(32 + 4 + certificate.length + 4 + encryptedSignature.length);
  publicKey.copy(response, 0);
  response.writeUInt32BE(certificate.length, 32);
  certificate.copy(response, 36);
  response.writeUInt32BE(encryptedSignature.length, 36 + certificate.length);
  encryptedSignature.copy(response, 40 + certificate.length);
  return response;
}

function buildBaaResponse(publicKey, leaf, encryptedSignature, baicBlob) {
  const response = Buffer.alloc(
    32 + 4 + leaf.length + 4 + encryptedSignature.length + 4 + baicBlob.length,
  );
  publicKey.copy(response, 0);
  let offset = 32;
  response.writeUInt32BE(leaf.length, offset);
  offset += 4;
  leaf.copy(response, offset);
  offset += leaf.length;
  response.writeUInt32BE(encryptedSignature.length, offset);
  offset += 4;
  encryptedSignature.copy(response, offset);
  offset += encryptedSignature.length;
  response.writeUInt32BE(baicBlob.length, offset);
  offset += 4;
  baicBlob.copy(response, offset);
  return response;
}

/**
 * Handle one `/auth-setup` body. Returns the binary response, or `null` for a malformed body
 * or a zero shared secret, matching the app.
 */
export function handleMfiSap(body, authenticator) {
  const request = Buffer.from(body);
  if (request.length !== 33 || request[0] !== 0x01) return null;
  const peerPublicKey = request.subarray(1);

  const pair = x25519Generate();
  let shared;
  try {
    shared = x25519Shared(pair.privateKey, peerPublicKey);
  } catch {
    return null;
  }
  if (shared.every((byte) => byte === 0)) return null;

  const { aesKey, aesIv } = keySchedule(shared);

  if (authenticator.certificateType === 'baa') {
    const certificates = authenticator.baaCertificates();
    const signature = authenticator.signChallenge(concat(pair.rawPublicKey, peerPublicKey));
    const encrypted = aesCtr128(aesKey, aesIv, signature);
    return buildBaaResponse(
      pair.rawPublicKey,
      certificates.leaf,
      encrypted,
      encodeBaaIntermediate(certificates.intermediate),
    );
  }

  const certificate = Buffer.from(authenticator.readCertificate());
  const input = authenticator.protocolMajor() === 2
    ? sha1(pair.rawPublicKey, peerPublicKey)
    : sha256(pair.rawPublicKey, peerPublicKey);
  const signature = authenticator.signChallenge(input);
  const encrypted = aesCtr128(aesKey, aesIv, signature);
  return buildMfiResponse(pair.rawPublicKey, certificate, encrypted);
}

/** Peer-side driver used by tests and the CLI selftest. */
export function runMfiSapPeer(authenticator, { protocolMajor = null } = {}) {
  const major = protocolMajor ?? authenticator.protocolMajor();
  const peer = x25519Generate();
  const response = handleMfiSap(Buffer.concat([Buffer.from([0x01]), peer.rawPublicKey]), authenticator);
  if (!response) throw new Error('SAP handler rejected the request');

  const accPublicKey = response.subarray(0, 32);
  let offset = 32;
  const certificateLength = response.readUInt32BE(offset);
  offset += 4;
  const certificate = response.subarray(offset, offset + certificateLength);
  offset += certificateLength;
  const encryptedLength = response.readUInt32BE(offset);
  offset += 4;
  const encrypted = response.subarray(offset, offset + encryptedLength);
  offset += encryptedLength;

  const shared = x25519Shared(peer.privateKey, accPublicKey);
  const { aesKey, aesIv } = keySchedule(shared);
  const signature = aesCtr128(aesKey, aesIv, encrypted);

  if (authenticator.certificateType === 'baa') {
    const digest = crypto
      .createHash('sha256')
      .update(concat(accPublicKey, peer.rawPublicKey))
      .digest();
    return {
      ok: verifyDigest(authenticator.publicKey(), digest, signature),
      signature,
      certificate,
      accPublicKey,
      baa: true,
    };
  }

  const digest = major === 2
    ? sha1(accPublicKey, peer.rawPublicKey)
    : sha256(accPublicKey, peer.rawPublicKey);
  const verify = major === 2 ? verifyRawDigest : verifyDigest;
  return {
    ok: verify(authenticator.publicKey(), digest, signature),
    signature,
    certificate,
    accPublicKey,
    baa: false,
  };
}
