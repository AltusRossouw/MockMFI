/**
 * P-256 helpers with the same semantics as DiPlay's local signer: the caller supplies the
 * digest and the signature is the raw 64-byte r||s form, i.e. `NONEwithECDSA` plus the app's
 * DER-to-raw conversion.
 *
 * Node's `crypto.sign(null, ...)` is not usable for that: with an EC key this release feeds the
 * input through the key's default digest (SHA-256), so the "digest" would be hashed again. The
 * arithmetic below is plain BigInt ECDSA over P-256, which keeps the model byte-accurate.
 */

import crypto from 'node:crypto';

export const P256_ORDER = BigInt(
  '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
);

const P = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
const A = P - 3n;
const G = {
  x: BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
  y: BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
};

const mod = (value, m) => ((value % m) + m) % m;

function modInverse(value, m) {
  let a = mod(value, m);
  if (a === 0n) throw new Error('no inverse for zero');
  let b = m;
  let x = 1n;
  let y = 0n;
  while (b !== 0n) {
    const q = a / b;
    [a, b] = [b, a - q * b];
    [x, y] = [y, x - q * y];
  }
  if (a !== 1n) throw new Error('value is not invertible');
  return mod(x, m);
}

function pointDouble(point) {
  if (point === null) return null;
  const slope = mod((3n * point.x * point.x + A) * modInverse(2n * point.y, P), P);
  const x = mod(slope * slope - 2n * point.x, P);
  return { x, y: mod(slope * (point.x - x) - point.y, P) };
}

function pointAdd(left, right) {
  if (left === null) return right;
  if (right === null) return left;
  if (left.x === right.x) {
    if (mod(left.y + right.y, P) === 0n) return null;
    return pointDouble(left);
  }
  const slope = mod((right.y - left.y) * modInverse(right.x - left.x, P), P);
  const x = mod(slope * slope - left.x - right.x, P);
  return { x, y: mod(slope * (left.x - x) - left.y, P) };
}

function scalarMultiply(scalar, point) {
  let result = null;
  let addend = point;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointDouble(addend);
    k >>= 1n;
  }
  return result;
}

function bytesToScalar(bytes) {
  if (bytes.length === 0) return 0n;
  return BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
}

function scalarTo32(value) {
  const hex = mod(value, P).toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}

function privateScalar(privateKey) {
  const jwk = privateKey.export({ format: 'jwk' });
  if (!jwk || typeof jwk.d !== 'string') throw new Error('not a private P-256 key');
  return bytesToScalar(Buffer.from(jwk.d, 'base64url'));
}

function publicPoint(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  if (!jwk || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new Error('not a public P-256 key');
  }
  return {
    x: bytesToScalar(Buffer.from(jwk.x, 'base64url')),
    y: bytesToScalar(Buffer.from(jwk.y, 'base64url')),
  };
}

function randomScalar() {
  for (;;) {
    const candidate = bytesToScalar(crypto.randomBytes(32));
    if (candidate > 0n && candidate < P256_ORDER) return candidate;
  }
}

function signScalar(privateKey, digest) {
  const d = privateScalar(privateKey);
  const z = bytesToScalar(digest);
  for (;;) {
    const k = randomScalar();
    const point = scalarMultiply(k, G);
    if (point === null) continue;
    const r = mod(point.x, P256_ORDER);
    if (r === 0n) continue;
    const s = mod(modInverse(k, P256_ORDER) * (z + r * d), P256_ORDER);
    if (s === 0n) continue;
    return Buffer.concat([scalarTo32(r), scalarTo32(s)]);
  }
}

function verifyScalar(publicKey, digest, signature) {
  if (!Buffer.isBuffer(signature) || signature.length !== 64) return false;
  const r = bytesToScalar(signature.subarray(0, 32));
  const s = bytesToScalar(signature.subarray(32, 64));
  if (r <= 0n || r >= P256_ORDER || s <= 0n || s >= P256_ORDER) return false;
  const z = bytesToScalar(digest);
  const w = modInverse(s, P256_ORDER);
  const point = pointAdd(
    scalarMultiply(mod(z * w, P256_ORDER), G),
    scalarMultiply(mod(r * w, P256_ORDER), publicPoint(publicKey)),
  );
  if (point === null) return false;
  return mod(point.x, P256_ORDER) === r;
}

export function generateP256() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

export function signDigest(privateKey, digest) {
  if (!Buffer.isBuffer(digest) || digest.length !== 32) {
    throw new RangeError(`expected a 32-byte digest, got ${digest?.length}`);
  }
  return signScalar(privateKey, digest);
}

/**
 * Sign a shorter raw digest (for example a 20-byte SHA-1 value on the protocol-major-2 SAP
 * path). The app's local P-256 provider only accepts 32 bytes; this variant exists for the
 * modelled coprocessor/remote-shaped authenticator.
 */
export function signRawDigest(privateKey, digest) {
  if (!Buffer.isBuffer(digest) || digest.length < 1 || digest.length > 32) {
    throw new RangeError(`expected a 1..32-byte digest, got ${digest?.length}`);
  }
  return signScalar(privateKey, digest);
}

export function verifyDigest(publicKey, digest, signature) {
  if (!Buffer.isBuffer(digest) || digest.length !== 32) return false;
  try {
    return verifyScalar(publicKey, digest, signature);
  } catch {
    return false;
  }
}

export function verifyRawDigest(publicKey, digest, signature) {
  if (!Buffer.isBuffer(digest) || digest.length < 1 || digest.length > 32) return false;
  try {
    return verifyScalar(publicKey, digest, signature);
  } catch {
    return false;
  }
}

function readTlv(buffer, offset) {
  if (offset + 2 > buffer.length) throw new Error('truncated DER value');
  const tag = buffer[offset];
  let length = buffer[offset + 1];
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw new Error('unsupported DER length');
    if (offset + 2 + count > buffer.length) throw new Error('truncated DER length');
    length = 0;
    for (let index = 0; index < count; index += 1) {
      length = (length << 8) | buffer[offset + 2 + index];
    }
    header += count;
  }
  if (offset + header + length > buffer.length) throw new Error('truncated DER value');
  return { tag, value: buffer.subarray(offset + header, offset + header + length), end: offset + header + length };
}

function integerTo32(value) {
  let bytes = value;
  if (bytes.length === 0) throw new Error('empty ECDSA integer');
  if (bytes[0] === 0x00) {
    // A leading zero is DER sign padding; strip it and treat the rest as the magnitude.
    while (bytes.length > 1 && bytes[0] === 0x00) bytes = bytes.subarray(1);
  } else if ((bytes[0] & 0x80) !== 0) {
    throw new Error('negative ECDSA integer');
  }
  if (bytes.length > 32) throw new Error('ECDSA integer exceeds 256 bits');
  const out = Buffer.alloc(32);
  bytes.copy(out, 32 - bytes.length);
  return out;
}

/** Convert a DER `SEQUENCE { INTEGER r, INTEGER s }` to 64-byte r||s. */
export function derToRaw(der) {
  const buffer = Buffer.from(der);
  const sequence = readTlv(buffer, 0);
  if (sequence.tag !== 0x30) throw new Error('ECDSA signature is not a SEQUENCE');
  if (sequence.end !== buffer.length) throw new Error('trailing bytes after ECDSA SEQUENCE');

  let offset = 0;
  const integers = [];
  while (offset < sequence.value.length) {
    const item = readTlv(sequence.value, offset);
    if (item.tag !== 0x02) throw new Error('ECDSA signature contains a non-INTEGER');
    integers.push(integerTo32(item.value));
    offset = item.end;
  }
  if (integers.length !== 2) throw new Error('ECDSA signature must contain two integers');
  return Buffer.concat(integers);
}

function encodeInteger(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00) start += 1;
  let value = bytes.subarray(start);
  if (value[0] & 0x80) value = Buffer.concat([Buffer.from([0x00]), value]);
  const length = value.length;
  if (length > 0x7f) throw new Error('ECDSA integer too large to encode');
  return Buffer.concat([Buffer.from([0x02, length]), value]);
}

/** Convert 64-byte r||s to a DER `SEQUENCE { INTEGER r, INTEGER s }`. */
export function rawToDer(raw) {
  if (!Buffer.isBuffer(raw) || raw.length !== 64) throw new RangeError('expected 64-byte raw signature');
  const r = encodeInteger(raw.subarray(0, 32));
  const s = encodeInteger(raw.subarray(32, 64));
  const body = Buffer.concat([r, s]);
  if (body.length > 0x7f) throw new Error('ECDSA DER signature too large');
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/** True when the 32-byte values are valid P-256 scalars (non-zero, below the order). */
export function isValidScalarPair(raw) {
  if (!Buffer.isBuffer(raw) || raw.length !== 64) return false;
  const r = BigInt(`0x${raw.subarray(0, 32).toString('hex')}`);
  const s = BigInt(`0x${raw.subarray(32, 64).toString('hex')}`);
  return r > 0n && r < P256_ORDER && s > 0n && s < P256_ORDER;
}
