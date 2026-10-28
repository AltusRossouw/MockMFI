/**
 * Remote MFi HTTP service model.
 *
 * Implements the contract consumed by DiPlay's `RemoteMfiAuthenticationClient`:
 *   GET  /mfi/certificate
 *   POST /mfi/sign
 *   POST /mfi/reset
 */

import crypto from 'node:crypto';
import http from 'node:http';

import { base64, fromBase64 } from './bytes.js';

export const MAX_BODY_BYTES = 2 * 1024 * 1024;
export const MAX_CERTIFICATE_BYTES = 65525;
export const MAX_CHALLENGE_BYTES = 128;

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function sendJson(response, status, body) {
  if (response.destroyed || response.writableEnded) return;
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
  });
  response.end(payload);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    request.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        const error = new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`);
        error.status = 413;
        reject(error);
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function parseJsonBody(buffer) {
  if (buffer.length === 0) return {};
  try {
    const value = JSON.parse(buffer.toString('utf8'));
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('body must be a JSON object');
    }
    return value;
  } catch (error) {
    const failure = new Error(`invalid JSON body: ${error.message}`);
    failure.status = 400;
    throw failure;
  }
}

export function createRemoteMfiServer({
  authenticator,
  token = null,
  signDelayMs = 0,
  host = '127.0.0.1',
  port = 0,
} = {}) {
  if (!authenticator) throw new Error('authenticator is required');

  /** requestId -> { challenge: Buffer, signature: Buffer } */
  const signatures = new Map();
  const signRequests = [];
  let certificateRequests = 0;

  const hooks = {
    /** Delay the next sign request (once) to exercise client retry. */
    delayNextSignMs: null,
    /** Fail the next sign request with HTTP 500. */
    failNextSign: false,
    /** Fail the next certificate request with HTTP 500. */
    failNextCertificate: false,
    /** Corrupt the certificate SHA-256 field to exercise client validation. */
    corruptCertificateSha: false,
    /** Override the certificate `type` field (e.g. "unknown"). */
    certificateTypeOverride: null,
  };

  const server = http.createServer(async (request, response) => {
    try {
      if (request.method === 'OPTIONS') {
        response.writeHead(204);
        response.end();
        return;
      }

      if (token !== null) {
        const authorization = request.headers.authorization ?? '';
        if (authorization !== `Bearer ${token}`) {
          sendJson(response, 401, { detail: 'unauthorized' });
          return;
        }
      }

      const url = new URL(request.url ?? '/', `http://${host}`);
      const path = url.pathname;

      if (request.method === 'GET' && path === '/mfi/certificate') {
        certificateRequests += 1;
        if (hooks.failNextCertificate) {
          hooks.failNextCertificate = false;
          sendJson(response, 500, { detail: 'certificate unavailable' });
          return;
        }
        const certificate = Buffer.from(authenticator.readCertificate());
        const body = {
          protocolMajor: authenticator.protocolMajor(),
          certificate: base64(certificate),
          certificateSha256: hooks.corruptCertificateSha
            ? '00'.repeat(32)
            : sha256Hex(certificate),
        };
        const type = hooks.certificateTypeOverride ?? authenticator.certificateType;
        if (type !== 'mfi') body.type = type;
        sendJson(response, 200, body);
        return;
      }

      if (request.method === 'POST' && path === '/mfi/sign') {
        const body = parseJsonBody(await readBody(request));
        if (typeof body.challenge !== 'string') {
          sendJson(response, 400, { detail: "missing 'challenge'" });
          return;
        }
        let challenge;
        try {
          challenge = fromBase64(body.challenge);
        } catch {
          sendJson(response, 400, { detail: "invalid 'challenge' base64" });
          return;
        }
        if (challenge.length < 1 || challenge.length > MAX_CHALLENGE_BYTES) {
          sendJson(response, 400, {
            detail: `challenge must be 1..${MAX_CHALLENGE_BYTES} bytes`,
          });
          return;
        }
        const requestId = typeof body.requestId === 'string' ? body.requestId : '';
        signRequests.push({ requestId, challenge: Buffer.from(challenge) });

        const cached = signatures.get(requestId);
        if (cached) {
          if (!cached.challenge.equals(challenge)) {
            sendJson(response, 409, { detail: 'requestId reused with a different challenge' });
            return;
          }
          sendJson(response, 200, { signature: base64(cached.signature), requestId });
          return;
        }

        if (hooks.failNextSign) {
          hooks.failNextSign = false;
          sendJson(response, 500, { detail: 'sign failed' });
          return;
        }

        const delay = hooks.delayNextSignMs ?? (signRequests.length === 1 ? signDelayMs : 0);
        hooks.delayNextSignMs = null;
        if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));

        const signature = Buffer.from(authenticator.signChallenge(challenge));
        signatures.set(requestId, { challenge: Buffer.from(challenge), signature });
        sendJson(response, 200, { signature: base64(signature), requestId });
        return;
      }

      if (request.method === 'POST' && path === '/mfi/reset') {
        await readBody(request);
        signatures.clear();
        sendJson(response, 200, { detail: '' });
        return;
      }

      sendJson(response, 404, { detail: 'not found' });
    } catch (error) {
      const status = error.status ?? 500;
      sendJson(response, status, { detail: error.message });
    }
  });

  server.model = {
    hooks,
    signatures,
    signRequests,
    get certificateRequests() {
      return certificateRequests;
    },
    get cachedRequestIds() {
      return [...signatures.keys()];
    },
  };
  server.host = host;
  server.port = port;

  return server;
}

export function listen(server, { host = '127.0.0.1', port = 0 } = {}) {
  return new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once('error', onError);
    server.listen(port, host, () => {
      server.removeListener('error', onError);
      const address = server.address();
      resolve({
        server,
        host,
        port: address.port,
        url: `http://${host}:${address.port}`,
      });
    });
  });
}

export function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}
