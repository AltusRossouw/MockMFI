/**
 * iAP2 CSM framing and parameter lists.
 *
 * Frame:     0x4040 | u16 length | u16 messageId | body
 * Parameter: u16 length | u16 parameterId | payload
 *
 * All integers are big-endian. `length` includes the 6-byte frame header.
 */

import { u16 } from './bytes.js';

export const CSM_START = 0x4040;
export const CSM_HEADER_BYTES = 6;
export const CSM_MAX_FRAME_BYTES = 0xffff;
export const CSM_MAX_PARAM_BYTES = 0xffff;

export function encodeParam(id, payload) {
  if (!Number.isInteger(id) || id < 0 || id > 0xffff) throw new RangeError('parameter id out of range');
  const body = Buffer.from(payload ?? Buffer.alloc(0));
  const length = 4 + body.length;
  if (length > CSM_MAX_PARAM_BYTES) throw new RangeError('parameter too large');
  const header = Buffer.alloc(4);
  header.writeUInt16BE(length, 0);
  header.writeUInt16BE(id, 2);
  return Buffer.concat([header, body]);
}

export function encodeFrame(messageId, payload = Buffer.alloc(0)) {
  if (!Number.isInteger(messageId) || messageId < 0 || messageId > 0xffff) {
    throw new RangeError('message id out of range');
  }
  const body = Buffer.from(payload);
  const length = CSM_HEADER_BYTES + body.length;
  if (length > CSM_MAX_FRAME_BYTES) throw new RangeError('frame too large');
  const header = Buffer.alloc(4);
  header.writeUInt16BE(CSM_START, 0);
  header.writeUInt16BE(length, 2);
  return Buffer.concat([header, u16(messageId), body]);
}

export function parseParams(payload) {
  const params = [];
  let offset = 0;
  while (offset < payload.length) {
    if (offset + 4 > payload.length) throw new Error('truncated parameter header');
    const length = payload.readUInt16BE(offset);
    if (length < 4 || offset + length > payload.length) throw new Error('invalid parameter length');
    const id = payload.readUInt16BE(offset + 2);
    params.push({ id, payload: Buffer.from(payload.subarray(offset + 4, offset + length)) });
    offset += length;
  }
  return params;
}

export function buildFrame(messageId, params) {
  const body = Buffer.concat(params.map((param) => encodeParam(param.id, param.payload)));
  return encodeFrame(messageId, body);
}

export function requireParam(params, id, name = `parameter ${id}`) {
  const found = params.find((param) => param.id === id);
  if (!found) throw new Error(`missing ${name}`);
  return found.payload;
}

/**
 * Incremental CSM decoder. Tolerates arbitrary chunking, concatenated frames, and garbage
 * before a `0x4040` start marker. Invalid lengths are skipped one byte at a time.
 */
export class CsmDecoder {
  constructor() {
    this.buffer = Buffer.alloc(0);
  }

  push(chunk) {
    if (!chunk || chunk.length === 0) return [];
    this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)]);
    const frames = [];

    for (;;) {
      if (this.buffer.length < 2) break;

      let start = -1;
      for (let index = 0; index + 1 < this.buffer.length; index += 1) {
        if (this.buffer[index] === 0x40 && this.buffer[index + 1] === 0x40) {
          start = index;
          break;
        }
      }

      if (start < 0) {
        // Retain a trailing 0x40; it may be the first half of the next start marker.
        this.buffer = this.buffer[this.buffer.length - 1] === 0x40
          ? this.buffer.subarray(this.buffer.length - 1)
          : Buffer.alloc(0);
        break;
      }

      if (start > 0) {
        this.buffer = this.buffer.subarray(start);
        continue;
      }

      if (this.buffer.length < CSM_HEADER_BYTES) break;

      const length = this.buffer.readUInt16BE(2);
      if (length < CSM_HEADER_BYTES) {
        this.buffer = this.buffer.subarray(1);
        continue;
      }
      if (this.buffer.length < length) break;

      const messageId = this.buffer.readUInt16BE(4);
      const payload = Buffer.from(this.buffer.subarray(CSM_HEADER_BYTES, length));
      frames.push({ messageId, payload });
      this.buffer = this.buffer.subarray(length);
    }

    return frames;
  }
}
