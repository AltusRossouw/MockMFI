import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CsmDecoder,
  buildFrame,
  encodeFrame,
  encodeParam,
  parseParams,
  requireParam,
} from '../src/csm.js';

test('empty 0xAA00 frame vector', () => {
  assert.equal(encodeFrame(0xaa00).toString('hex'), '40400006aa00');
});

test('0xAA01 certificate frame vector', () => {
  const frame = buildFrame(0xaa01, [{ id: 0, payload: Buffer.from('ABC') }]);
  assert.equal(frame.toString('hex'), '4040000daa0100070000414243');
});

test('0xAA02 and 0xAA03 lengths', () => {
  const challenge = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  const challengeFrame = buildFrame(0xaa02, [{ id: 0, payload: challenge }]);
  assert.equal(challengeFrame.readUInt16BE(2), 6 + 4 + 32);
  assert.equal(challengeFrame.readUInt16BE(4), 0xaa02);

  const signature = Buffer.alloc(64, 0x80);
  const signatureFrame = buildFrame(0xaa03, [{ id: 0, payload: signature }]);
  assert.equal(signatureFrame.readUInt16BE(2), 6 + 4 + 64);
  assert.equal(signatureFrame.readUInt16BE(4), 0xaa03);
});

test('parameter list round-trip', () => {
  const frame = buildFrame(0xaa01, [
    { id: 0, payload: Buffer.from([1, 2, 3]) },
    { id: 5, payload: Buffer.alloc(0) },
  ]);
  const params = parseParams(frame.subarray(6));
  assert.equal(params.length, 2);
  assert.equal(params[0].id, 0);
  assert.equal(params[0].payload.equals(Buffer.from([1, 2, 3])), true);
  assert.equal(params[1].id, 5);
  assert.equal(params[1].payload.length, 0);
  assert.equal(requireParam(params, 0).length, 3);
  assert.throws(() => requireParam(params, 9), /missing/);
});

test('decoder tolerates garbage, chunking, and concatenation', () => {
  const first = encodeFrame(0xaa00);
  const second = buildFrame(0xaa01, [{ id: 0, payload: Buffer.from('x') }]);
  const input = Buffer.concat([Buffer.from('junk-before-start'), first, second]);

  const decoder = new CsmDecoder();
  const frames = [];
  for (let offset = 0; offset < input.length; offset += 2) {
    frames.push(...decoder.push(input.subarray(offset, offset + 2)));
  }
  assert.equal(frames.length, 2);
  assert.equal(frames[0].messageId, 0xaa00);
  assert.equal(frames[1].messageId, 0xaa01);
  assert.equal(frames[1].payload.length, 5);
});

test('decoder skips an invalid length and resynchronizes', () => {
  const invalid = Buffer.from('40400001aabb', 'hex');
  const valid = encodeFrame(0xaa05);
  const frames = new CsmDecoder().push(Buffer.concat([invalid, valid]));
  assert.equal(frames.length, 1);
  assert.equal(frames[0].messageId, 0xaa05);
});

test('decoder retains a split start marker', () => {
  const frame = encodeFrame(0xaa00);
  const decoder = new CsmDecoder();
  assert.equal(decoder.push(Buffer.from([0x40])).length, 0);
  assert.equal(decoder.push(frame.subarray(1)).length, 1);
});

test('parameter and frame bounds', () => {
  assert.throws(() => encodeParam(0, Buffer.alloc(0x10000)), /too large/);
  assert.throws(() => encodeFrame(0, Buffer.alloc(0x10000)), /too large/);
  assert.throws(() => encodeFrame(0x10000, Buffer.alloc(0)), /message id/);
});
