import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';

import { auth } from './helpers.js';
import { base64 } from '../src/bytes.js';
import { verifyDigest } from '../src/ecdsa.js';
import {
  RemoteMfiClient,
  RemoteMfiHttpError,
  assertAllowedBaseUrl,
  isPrivateHost,
} from '../src/remote-client.js';
import { closeServer, createRemoteMfiServer, listen } from '../src/remote-server.js';

async function withServer(options, callback) {
  const authenticator = options.authenticator ?? auth();
  const server = createRemoteMfiServer({
    authenticator,
    host: '127.0.0.1',
    ...options,
  });
  const listening = await listen(server, { host: '127.0.0.1', port: 0 });
  try {
    await callback(listening, server, authenticator);
  } finally {
    await closeServer(server);
  }
}

test('reset, certificate, and sign round-trip', async () => {
  const authenticator = auth();
  await withServer({ authenticator }, async (listening, server) => {
    const client = new RemoteMfiClient(listening.url);
    await client.reset();
    assert.equal(await client.protocolMajor(), 3);

    const certificate = await client.readCertificate();
    assert.equal(certificate.equals(authenticator.readCertificate()), true);
    assert.equal(server.model.certificateRequests, 1, 'certificate is cached after the first call');

    const digest = crypto.createHash('sha256').update('remote-round-trip').digest();
    const signature = await client.signChallenge(digest);
    assert.equal(signature.length, 64);
    assert.equal(verifyDigest(authenticator.publicKey(), digest, signature), true);
    assert.equal(server.model.signRequests.length, 1);
  });
});

test('retries a timed-out sign with the same requestId', async () => {
  const authenticator = auth();
  await withServer({ authenticator, signDelayMs: 120 }, async (listening, server) => {
    const client = new RemoteMfiClient(listening.url, {
      readTimeoutMs: 25,
      maximumAttempts: 2,
    });
    const digest = crypto.createHash('sha256').update('retry-sign').digest();
    const signature = await client.signChallenge(digest);
    assert.equal(verifyDigest(authenticator.publicKey(), digest, signature), true);

    assert.equal(server.model.signRequests.length, 2);
    const [first, second] = server.model.signRequests;
    assert.equal(first.requestId, second.requestId);
    assert.equal(first.challenge.equals(second.challenge), true);
  });
});

test('retries a retryable 500', async () => {
  const authenticator = auth();
  await withServer({ authenticator }, async (listening, server) => {
    server.model.hooks.failNextSign = true;
    const client = new RemoteMfiClient(listening.url, { maximumAttempts: 2 });
    const digest = crypto.createHash('sha256').update('retry-500').digest();
    const signature = await client.signChallenge(digest);
    assert.equal(verifyDigest(authenticator.publicKey(), digest, signature), true);
    assert.equal(server.model.signRequests.length, 2);
  });
});

test('does not retry when attempts are exhausted', async () => {
  await withServer({}, async (listening, server) => {
    server.model.hooks.failNextSign = true;
    const client = new RemoteMfiClient(listening.url, { maximumAttempts: 1 });
    const digest = crypto.createHash('sha256').update('no-retry').digest();
    await assert.rejects(
      () => client.signChallenge(digest),
      (error) => error instanceof RemoteMfiHttpError && error.statusCode === 500,
    );
  });
});

test('does not retry a non-retryable 400', async () => {
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests += 1;
    response.writeHead(400, { 'Content-Type': 'application/json' });
    response.end('{"detail":"bad request"}');
  });
  const listening = await listen(server, { host: '127.0.0.1', port: 0 });
  try {
    const client = new RemoteMfiClient(listening.url, { maximumAttempts: 2 });
    await assert.rejects(
      () => client.readCertificate(),
      (error) => error instanceof RemoteMfiHttpError && error.statusCode === 400,
    );
    assert.equal(requests, 1);
  } finally {
    await closeServer(server);
  }
});

test('bearer token is enforced', async () => {
  await withServer({ token: 'secret' }, async (listening) => {
    const bad = new RemoteMfiClient(listening.url, {
      token: 'wrong',
      maximumAttempts: 1,
    });
    await assert.rejects(
      () => bad.readCertificate(),
      (error) => error instanceof RemoteMfiHttpError && error.statusCode === 401,
    );

    const good = new RemoteMfiClient(listening.url, { token: 'secret' });
    assert.ok((await good.readCertificate()).length > 0);
  });
});

test('certificate SHA-256 mismatch is rejected', async () => {
  await withServer({}, async (listening, server) => {
    server.model.hooks.corruptCertificateSha = true;
    const client = new RemoteMfiClient(listening.url, { maximumAttempts: 1 });
    await assert.rejects(() => client.readCertificate(), /SHA-256/);
  });
});

test('unknown certificate type is rejected', async () => {
  await withServer({}, async (listening, server) => {
    server.model.hooks.certificateTypeOverride = 'unknown';
    const client = new RemoteMfiClient(listening.url, { maximumAttempts: 1 });
    await assert.rejects(() => client.readCertificate(), /Unsupported/);
  });
});

test('certificate failure surfaces the HTTP status', async () => {
  await withServer({}, async (listening, server) => {
    server.model.hooks.failNextCertificate = true;
    const client = new RemoteMfiClient(listening.url, { maximumAttempts: 1 });
    await assert.rejects(
      () => client.readCertificate(),
      (error) => error instanceof RemoteMfiHttpError && error.statusCode === 500,
    );
  });
});

test('reset clears the server signature cache', async () => {
  await withServer({}, async (listening, server) => {
    const client = new RemoteMfiClient(listening.url);
    const digest = crypto.createHash('sha256').update('reset-cache').digest();
    await client.signChallenge(digest);
    assert.equal(server.model.signatures.size, 1);
    await client.reset();
    assert.equal(server.model.signatures.size, 0);
  });
});

test('a requestId cannot be reused with a different challenge', async () => {
  await withServer({}, async (listening) => {
    const requestId = 'fixed-request-id';
    const first = await fetch(`${listening.url}/mfi/sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge: base64(Buffer.alloc(32, 1)), requestId }),
    });
    assert.equal(first.status, 200);

    const second = await fetch(`${listening.url}/mfi/sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge: base64(Buffer.alloc(32, 2)), requestId }),
    });
    assert.equal(second.status, 409);
  });
});

test('BAA package is served and repackaged for iAP2', async () => {
  const authenticator = auth({ type: 'baa' });
  await withServer({ authenticator }, async (listening) => {
    const client = new RemoteMfiClient(listening.url);
    assert.equal(await client.certificateType(), 'baa');
    const certificate = await client.readCertificate();
    const pair = await client.baaCertificates();
    assert.equal(certificate.readUInt16BE(0), 4 + pair.leaf.length);
    assert.equal(certificate.length, 13 + pair.leaf.length + pair.intermediate.length);
  });
});

test('unknown paths return 404', async () => {
  await withServer({}, async (listening) => {
    const response = await fetch(`${listening.url}/unknown`);
    assert.equal(response.status, 404);
  });
});

test('cleartext host policy mirrors the private-network rule', () => {
  for (const host of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.2', '169.254.1.2', '100.64.0.1']) {
    assert.equal(isPrivateHost(host), true, host);
  }
  for (const host of ['example.com', '8.8.8.8', '172.32.0.1', '1.2.3']) {
    assert.equal(isPrivateHost(host), false, host);
  }
  assert.throws(() => new RemoteMfiClient('http://example.com'), /https/);
  assert.equal(new RemoteMfiClient('https://example.com').baseAddress, 'https://example.com');
  assert.equal(new RemoteMfiClient('http://127.0.0.1:8787').baseAddress, 'http://127.0.0.1:8787');
  assert.throws(() => assertAllowedBaseUrl('ftp://127.0.0.1'), /http/);
});
