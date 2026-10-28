/**
 * Mock CarPlay controller (phone) side: drives the iAP2 AccAuthentication exchange and
 * verifies the accessory's certificate and signature against the generated test PKI.
 */

import crypto from 'node:crypto';

import { CsmDecoder, buildFrame, encodeFrame } from './csm.js';
import { AUTH, certificateFrom, signatureFrom } from './iap2-auth.js';
import { verifyDigest } from './ecdsa.js';
import { runMfiSapPeer } from './sap.js';

export const APPLE_MFI_OID_DER = Buffer.from('06092a864886f763640624', 'hex');
export const TEST_MFI_OID_DER = Buffer.from('06092b0601040183b20301', 'hex');
export const TEST_BAA_OID_DER = Buffer.from('06092b0601040183b20302', 'hex');

export function hasAppleOid(der) {
  return Buffer.from(der).includes(APPLE_MFI_OID_DER);
}

export function hasTestOid(der, kind = 'mfi') {
  const marker = kind === 'baa' ? TEST_BAA_OID_DER : TEST_MFI_OID_DER;
  return Buffer.from(der).includes(marker);
}

/**
 * Verify one certificate against an issuer and the current time. This is a test-PKI check,
 * not Apple trust validation.
 */
export function verifyCertificate(leafDer, issuerDer) {
  let leaf;
  let issuer;
  try {
    leaf = new crypto.X509Certificate(leafDer);
    issuer = new crypto.X509Certificate(issuerDer);
  } catch (error) {
    return { ok: false, reason: `certificate parse failed: ${error.message}` };
  }
  const now = Date.now();
  if (Date.parse(leaf.validFrom) > now) return { ok: false, reason: 'certificate is not yet valid' };
  if (Date.parse(leaf.validTo) < now) return { ok: false, reason: 'certificate has expired' };
  if (!leaf.checkIssued(issuer)) {
    return { ok: false, reason: 'certificate was not issued by the supplied issuer' };
  }
  let signatureValid = false;
  try {
    signatureValid = leaf.verify(issuer.publicKey);
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) return { ok: false, reason: 'certificate signature does not verify' };
  if (hasAppleOid(leaf.raw)) {
    return { ok: false, reason: 'certificate carries the Apple MFi marker OID' };
  }
  return { ok: true, reason: 'ok' };
}

export function verifyChain(leafDer, intermediateDer, rootDer) {
  const leafToIntermediate = verifyCertificate(leafDer, intermediateDer);
  if (!leafToIntermediate.ok) return leafToIntermediate;
  const intermediateToRoot = verifyCertificate(intermediateDer, rootDer);
  if (!intermediateToRoot.ok) return intermediateToRoot;
  return { ok: true, reason: 'ok' };
}

class FrameEndpoint {
  constructor() {
    this.decoder = new CsmDecoder();
    this.inbox = [];
    this.waiters = [];
    this.peer = null;
  }

  send(buffer) {
    if (!this.peer) throw new Error('endpoint is not connected');
    this.peer.deliver(buffer);
  }

  deliver(buffer) {
    for (const frame of this.decoder.push(buffer)) {
      if (this.waiters.length > 0) this.waiters.shift()(frame);
      else this.inbox.push(frame);
    }
  }

  recv() {
    if (this.inbox.length > 0) return Promise.resolve(this.inbox.shift());
    return new Promise((resolve) => {
      this.waiters.push(resolve);
    });
  }
}

/** Two in-memory CSM endpoints: `phone.send()` reaches `accessory.recv()`, and vice versa. */
export function createFramePair() {
  const phone = new FrameEndpoint();
  const accessory = new FrameEndpoint();
  phone.peer = accessory;
  accessory.peer = phone;
  return { phone, accessory };
}

/**
 * Run the minimal phone-side exchange. The accessory responder must already be connected to
 * the other endpoint (see `runResponderLoop`).
 */
export async function runIap2Session(phone, authenticator, caDer, { challenge = null } = {}) {
  phone.send(encodeFrame(AUTH.REQUEST_CERTIFICATE));
  const certificateFrame = await phone.recv();
  const certificate = certificateFrom(certificateFrame);

  let certificateCheck;
  if (authenticator.certificateType === 'baa') {
    const pair = authenticator.baaCertificates();
    certificateCheck = verifyChain(pair.leaf, pair.intermediate, caDer);
  } else {
    certificateCheck = verifyCertificate(authenticator.leafDer, caDer);
    if (certificateCheck.ok && !certificate.equals(Buffer.from(authenticator.readCertificate()))) {
      certificateCheck = { ok: false, reason: 'presented certificate differs from the loaded certificate' };
    }
  }

  const value = challenge ? Buffer.from(challenge) : crypto.randomBytes(32);
  const reply = await (async () => {
    phone.send(buildFrame(AUTH.REQUEST_CHALLENGE, [{ id: 0, payload: value }]));
    return phone.recv();
  })();
  const signature = signatureFrom(reply);
  const verified = verifyDigest(authenticator.publicKey(), value, signature);

  phone.send(encodeFrame(AUTH.SUCCEEDED));

  return {
    certificate,
    certificateCheck,
    challenge: value,
    signature,
    verified,
  };
}

/** Responder loop used by tests and the CLI selftest. */
export async function runResponderLoop(accessory, responder) {
  for (;;) {
    const frame = await accessory.recv();
    const reply = responder.handle(frame);
    if (reply === null) return;
    accessory.send(reply);
  }
}

export function runSapSession(authenticator) {
  return runMfiSapPeer(authenticator);
}
