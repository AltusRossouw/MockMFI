/** Small buffer helpers. All multi-byte integers are big-endian. */

export function u16(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError(`u16 out of range: ${value}`);
  }
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value, 0);
  return buffer;
}

export function u32(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError(`u32 out of range: ${value}`);
  }
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value, 0);
  return buffer;
}

export function readU16(buffer, offset = 0) {
  if (offset + 2 > buffer.length) throw new RangeError('u16 read past end');
  return buffer.readUInt16BE(offset);
}

export function readU32(buffer, offset = 0) {
  if (offset + 4 > buffer.length) throw new RangeError('u32 read past end');
  return buffer.readUInt32BE(offset);
}

export function hex(buffer) {
  return Buffer.from(buffer).toString('hex');
}

export function fromHex(text) {
  if (typeof text !== 'string' || text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) {
    throw new Error('invalid hex');
  }
  return Buffer.from(text, 'hex');
}

export function base64(buffer) {
  return Buffer.from(buffer).toString('base64');
}

export function fromBase64(text) {
  if (typeof text !== 'string' || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new Error('invalid base64');
  }
  return Buffer.from(text, 'base64');
}

export function concat(...parts) {
  return Buffer.concat(parts.map((part) => Buffer.from(part)));
}

export function requireRange(buffer, min, max, name) {
  if (!Buffer.isBuffer(buffer) || buffer.length < min || buffer.length > max) {
    throw new RangeError(`${name} must be ${min}..${max} bytes, got ${buffer?.length}`);
  }
  return buffer;
}
