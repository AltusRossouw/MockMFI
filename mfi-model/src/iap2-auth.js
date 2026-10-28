/**
 * iAP2 CSM AccAuthentication responder (accessory side), mirroring
 * `Iap2MfiAuthenticationClient` and `Iap2AuthenticationMessages`.
 */

import { encodeFrame, encodeParam, buildFrame, parseParams, requireParam } from './csm.js';

export const AUTH = Object.freeze({
  REQUEST_CERTIFICATE: 0xaa00,
  CERTIFICATE: 0xaa01,
  REQUEST_CHALLENGE: 0xaa02,
  RESPONSE: 0xaa03,
  FAILED: 0xaa04,
  SUCCEEDED: 0xaa05,
  CERTIFICATE_SERIAL: 0xaa06,
});

export const MAX_CERTIFICATE_BYTES = 65525;
export const MAX_CHALLENGE_BYTES = 128;

export function certificateFrame(authenticator, maximumCertificateLength = MAX_CERTIFICATE_BYTES) {
  const certificate = Buffer.from(authenticator.readCertificate(maximumCertificateLength));
  if (authenticator.certificateType === 'baa') {
    const pair = authenticator.baaCertificates();
    return encodeFrame(
      AUTH.CERTIFICATE,
      Buffer.concat([
        encodeParam(0, pair.leaf),
        encodeParam(1, Buffer.from([1])),
        encodeParam(2, pair.intermediate),
      ]),
    );
  }
  return buildFrame(AUTH.CERTIFICATE, [{ id: 0, payload: certificate }]);
}

export function responseFrame(signature) {
  return buildFrame(AUTH.RESPONSE, [{ id: 0, payload: Buffer.from(signature) }]);
}

export function challengeFrom(frame) {
  if (frame.messageId !== AUTH.REQUEST_CHALLENGE) {
    throw new Error(`expected 0xAA02, got 0x${frame.messageId.toString(16)}`);
  }
  const params = parseParams(frame.payload);
  return requireParam(params, 0, 'iAP2 MFi challenge');
}

export function signatureFrom(frame) {
  if (frame.messageId !== AUTH.RESPONSE) {
    throw new Error(`expected 0xAA03, got 0x${frame.messageId.toString(16)}`);
  }
  const params = parseParams(frame.payload);
  return requireParam(params, 0, 'iAP2 MFi signature');
}

export function certificateFrom(frame) {
  if (frame.messageId !== AUTH.CERTIFICATE) {
    throw new Error(`expected 0xAA01, got 0x${frame.messageId.toString(16)}`);
  }
  return requireParam(parseParams(frame.payload), 0, 'iAP2 MFi certificate');
}

export class Iap2MfiResponder {
  constructor(authenticator, { maximumCertificateLength = MAX_CERTIFICATE_BYTES } = {}) {
    this.authenticator = authenticator;
    this.maximumCertificateLength = maximumCertificateLength;
  }

  /**
   * Handle one decoded frame. Returns the reply buffer, or `null` once the phone reports
   * AuthenticationSucceeded. Throws on AuthenticationFailed or an unexpected message.
   */
  handle(frame) {
    switch (frame.messageId) {
      case AUTH.REQUEST_CERTIFICATE:
        return certificateFrame(this.authenticator, this.maximumCertificateLength);
      case AUTH.REQUEST_CHALLENGE: {
        const challenge = challengeFrom(frame);
        if (challenge.length < 1 || challenge.length > MAX_CHALLENGE_BYTES) {
          throw new Error(`invalid iAP2 MFi challenge length ${challenge.length}`);
        }
        return responseFrame(this.authenticator.signChallenge(challenge));
      }
      case AUTH.FAILED:
        throw new Error('iPhone sent AuthenticationFailed');
      case AUTH.SUCCEEDED:
        return null;
      default:
        throw new Error(
          `unexpected iAP2 MFi message 0x${frame.messageId.toString(16).padStart(4, '0')}`,
        );
    }
  }
}
