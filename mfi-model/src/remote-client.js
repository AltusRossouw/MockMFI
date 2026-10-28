/**
 * Test client mirroring `RemoteMfiAuthenticationClient`: certificate caching, SHA-256
 * binding, BAA packaging, retry with a stable requestId, and the same error classes.
 */

import crypto from 'node:crypto';

import { base64, fromBase64 } from './bytes.js';
import { encodeParam } from './csm.js';

export class RemoteMfiHttpError extends Error {
  constructor(statusCode, detail) {
    super(`remote MFi request failed with HTTP ${statusCode}: ${detail}`);
    this.name = 'RemoteMfiHttpError';
    this.statusCode = statusCode;
    this.detail = detail;
  }
}

export function isPrivateHost(hostname) {
  const host = String(hostname).replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.local')) return true;
  if (host === '::1') return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const parts = host.split('.').map(Number);
    if (parts.some((part) => part > 255)) return false;
    const [a, b] = parts;
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  // Single-label names are trusted by their text in the app; mirror that narrow rule.
  return !host.includes('.') && /[a-z]/.test(host) && !host.startsWith('0x');
}

export function assertAllowedBaseUrl(address) {
  let url;
  try {
    url = new URL(address);
  } catch {
    throw new Error('remote MFi server address is not a valid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('remote MFi server address must use http:// or https://');
  }
  if (url.protocol === 'http:' && !isPrivateHost(url.hostname)) {
    throw new Error('remote MFi server must use https:// unless the host is on a private network');
  }
  return address.replace(/\/+$/, '');
}

function isRetryable(status) {
  return status === 408 || status === 429 || (status >= 500 && status <= 599);
}

export class RemoteMfiClient {
  constructor(
    serverAddress,
    { token = null, readTimeoutMs = 10000, maximumAttempts = 2 } = {},
  ) {
    this.baseAddress = assertAllowedBaseUrl(serverAddress);
    this.token = token;
    this.readTimeoutMs = readTimeoutMs;
    this.maximumAttempts = maximumAttempts;
    this.certificateInfo = null;
  }

  async reset() {
    this.certificateInfo = null;
    return this.request('POST', '/mfi/reset', '{}', false);
  }

  async protocolMajor() {
    return (await this.loadCertificateInfo()).protocolMajor;
  }

  async certificateType() {
    return (await this.loadCertificateInfo()).type;
  }

  async readCertificate(maximumOutputLength = 65525) {
    const info = await this.loadCertificateInfo();
    if (info.iap2Certificate.length < 1 || info.iap2Certificate.length > maximumOutputLength) {
      throw new RangeError(
        `remote certificate length ${info.iap2Certificate.length} is outside 1..${maximumOutputLength}`,
      );
    }
    return Buffer.from(info.iap2Certificate);
  }

  async baaCertificates() {
    const info = await this.loadCertificateInfo();
    if (!info.baaCertificates) throw new Error('remote MFi service is not using BAA certificates');
    return {
      leaf: Buffer.from(info.baaCertificates.leaf),
      intermediate: Buffer.from(info.baaCertificates.intermediate),
    };
  }

  async signChallenge(challenge) {
    const input = Buffer.from(challenge);
    if (input.length < 1 || input.length > 128) {
      throw new RangeError(`challenge must be 1..128 bytes, got ${input.length}`);
    }
    const requestId = crypto.randomUUID();
    const text = await this.request(
      'POST',
      '/mfi/sign',
      JSON.stringify({ challenge: base64(input), requestId }),
      true,
    );
    const body = JSON.parse(text);
    if (typeof body.signature !== 'string') throw new Error("remote response is missing 'signature'");
    const signature = fromBase64(body.signature);
    if (signature.length < 1 || signature.length > 65525) {
      throw new Error(`invalid remote signature length ${signature.length}`);
    }
    return signature;
  }

  async loadCertificateInfo() {
    if (this.certificateInfo) return this.certificateInfo;

    const text = await this.request('GET', '/mfi/certificate', null, true);
    const body = JSON.parse(text);
    if (!Number.isInteger(body.protocolMajor) || body.protocolMajor < 0 || body.protocolMajor > 0xff) {
      throw new Error(`invalid remote MFi protocol major ${body.protocolMajor}`);
    }
    const type = String(body.type ?? 'mfi').toLowerCase();
    if (type !== 'mfi' && type !== 'baa') {
      throw new Error(`Unsupported remote MFi certificate type '${type}'`);
    }
    if (typeof body.certificate !== 'string') throw new Error("remote response is missing 'certificate'");
    const certificate = fromBase64(body.certificate);
    if (certificate.length < 1 || certificate.length > 65525) {
      throw new Error(`invalid remote certificate length ${certificate.length}`);
    }
    if (typeof body.certificateSha256 !== 'string' || !/^[0-9a-fA-F]{64}$/.test(body.certificateSha256)) {
      throw new Error('certificateSha256 must contain 64 hexadecimal characters');
    }
    const expected = Buffer.from(body.certificateSha256, 'hex');
    const actual = crypto.createHash('sha256').update(certificate).digest();
    if (!crypto.timingSafeEqual(expected, actual)) {
      throw new Error('remote certificate SHA-256 does not match certificateSha256');
    }

    let iap2Certificate;
    let baaCertificates = null;
    if (type === 'baa') {
      if (certificate.length < 8) throw new Error('BAA certificate package is too short');
      const leafLength = certificate.readUInt32BE(0);
      const intermediateLength = certificate.readUInt32BE(4);
      if (
        leafLength <= 0 ||
        intermediateLength <= 0 ||
        8 + leafLength + intermediateLength !== certificate.length
      ) {
        throw new Error('BAA certificate package has invalid lengths');
      }
      const leaf = certificate.subarray(8, 8 + leafLength);
      const intermediate = certificate.subarray(8 + leafLength);
      baaCertificates = { leaf, intermediate };
      iap2Certificate = Buffer.concat([
        encodeParam(0, leaf),
        encodeParam(1, Buffer.from([1])),
        encodeParam(2, intermediate),
      ]);
    } else {
      iap2Certificate = certificate;
    }
    if (iap2Certificate.length > 65525) throw new Error('remote iAP2 certificate payload is too large');

    this.certificateInfo = {
      type,
      protocolMajor: body.protocolMajor,
      wireCertificate: certificate,
      iap2Certificate,
      baaCertificates,
    };
    return this.certificateInfo;
  }

  async request(method, path, body, retry) {
    const attempts = retry ? this.maximumAttempts : 1;
    let lastError;

    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        const headers = { Accept: 'application/json; charset=utf-8' };
        if (this.token) headers.Authorization = `Bearer ${this.token}`;
        const init = {
          method,
          headers,
          redirect: 'manual',
          cache: 'no-store',
          signal: AbortSignal.timeout(this.readTimeoutMs),
        };
        if (body !== null && body !== undefined) {
          headers['Content-Type'] = 'application/json; charset=utf-8';
          init.body = body;
        }

        const response = await fetch(`${this.baseAddress}${path}`, init);
        const text = await response.text();
        if (response.ok) return text;

        let detail = `HTTP ${response.status}`;
        try {
          const parsed = JSON.parse(text);
          if (typeof parsed.detail === 'string' && parsed.detail.trim()) detail = parsed.detail;
        } catch {
          // Keep the status-only detail.
        }
        const error = new RemoteMfiHttpError(response.status, detail);
        if (!isRetryable(response.status) || attempt + 1 >= attempts) throw error;
        lastError = error;
      } catch (error) {
        if (error instanceof RemoteMfiHttpError) throw error;
        lastError = error;
        if (attempt + 1 >= attempts) {
          throw new Error(`remote MFi request failed: ${error.message}`);
        }
      }
    }
    throw lastError;
  }
}
