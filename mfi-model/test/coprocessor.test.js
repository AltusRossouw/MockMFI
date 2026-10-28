import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CoprocessorModel,
  I2cNack,
  ScriptedTransport,
  readStep,
  selectStep,
  writeStep,
} from '../src/coprocessor.js';

function fake({ certificate = Buffer.alloc(300, 0x5a), signature = Buffer.alloc(128, 0xa5) } = {}) {
  return {
    certificateType: 'mfi',
    protocolMajor: () => 3,
    readCertificate: () => Buffer.from(certificate),
    signChallenge: () => Buffer.from(signature),
  };
}

function ops(model, address = 0x10) {
  return {
    select: (register) => model.transaction(address, Buffer.from([register]), 0),
    read: (count) => model.transaction(address, Buffer.alloc(0), count),
    write: (register, data) => model.transaction(
      address,
      Buffer.concat([Buffer.from([register]), Buffer.from(data)]),
      0,
    ),
  };
}

test('certificate is read in 128-byte windows', () => {
  const certificate = Buffer.from(Array.from({ length: 300 }, (_, index) => index & 0xff));
  const model = new CoprocessorModel({ authenticator: fake({ certificate }) });
  const { select, read } = ops(model);

  select(0x30);
  assert.equal(read(2).readUInt16BE(0), 300);

  const parts = [];
  for (const [register, count] of [[0x31, 128], [0x32, 128], [0x33, 44]]) {
    select(register);
    parts.push(read(count));
  }
  assert.equal(Buffer.concat(parts).equals(certificate), true);
});

test('challenge signing returns the dynamic response length', () => {
  const signature = Buffer.from(Array.from({ length: 128 }, (_, index) => (0xa0 + index) & 0xff));
  const model = new CoprocessorModel({ authenticator: fake({ signature }) });
  const { select, read, write } = ops(model);
  const challenge = Buffer.alloc(20, 0x11);

  write(0x20, Buffer.from([0x00, 0x14]));
  write(0x21, challenge);
  write(0x10, Buffer.from([0x01]));

  select(0x10);
  assert.equal(read(1)[0], 0x10);
  select(0x11);
  assert.equal(read(2).readUInt16BE(0), 128);
  select(0x12);
  assert.equal(read(128).equals(signature), true);
});

test('failed authentication exposes a best-effort error code', () => {
  const model = new CoprocessorModel({
    authenticator: fake(),
    failAuth: true,
    errorCode: 0x42,
  });
  const { select, read, write } = ops(model);

  write(0x20, Buffer.from([0x00, 0x20]));
  write(0x21, Buffer.alloc(32, 1));
  write(0x10, Buffer.from([0x01]));

  select(0x10);
  assert.equal(read(1)[0], 0xff);
  select(0x05);
  assert.equal(read(1)[0], 0x42);
});

test('invalid challenge length fails closed', () => {
  const model = new CoprocessorModel({ authenticator: fake() });
  const { select, read, write } = ops(model);

  write(0x20, Buffer.from([0x00, 0x00]));
  write(0x10, Buffer.from([0x01]));

  select(0x10);
  assert.equal(read(1)[0], 0xff);
  select(0x05);
  assert.equal(read(1)[0], 0x01);
});

test('out-of-range windows and short reads are NACKed', () => {
  const model = new CoprocessorModel({ authenticator: fake() });
  const { select, read } = ops(model);

  select(0x40);
  assert.throws(() => read(1), I2cNack);

  select(0x12);
  assert.throws(() => read(1), I2cNack);

  select(0x00);
  assert.throws(() => read(2), I2cNack);
});

test('wrong address and unknown registers are NACKed', () => {
  const model = new CoprocessorModel({ authenticator: fake(), address7Bit: 0x10 });
  assert.throws(() => model.transaction(0x11, Buffer.from([0x00]), 0), I2cNack);
  const { select, read } = ops(model);
  select(0x7f);
  assert.throws(() => read(1), I2cNack);
});

test('auth status can be delayed without blocking', async () => {
  const model = new CoprocessorModel({ authenticator: fake(), signDelayMs: 20 });
  const { select, read, write } = ops(model);

  write(0x20, Buffer.from([0x00, 0x20]));
  write(0x21, Buffer.alloc(32, 1));
  write(0x10, Buffer.from([0x01]));

  select(0x10);
  assert.equal(read(1)[0], 0x00);
  await new Promise((resolve) => setTimeout(resolve, 30));
  select(0x10);
  assert.equal(read(1)[0], 0x10);
});

test('discovery rejects the floating-bus value and accepts the next candidate', () => {
  const floating = new CoprocessorModel({
    authenticator: fake(),
    address7Bit: 0x10,
    deviceVersion: 0xff,
  });
  const real = new CoprocessorModel({
    authenticator: fake(),
    address7Bit: 0x11,
    deviceVersion: 0x07,
  });

  function probe(model, address) {
    model.transaction(address, Buffer.from([0x00]), 0);
    return model.transaction(address, Buffer.alloc(0), 1)[0];
  }

  assert.equal(probe(floating, 0x10), 0xff);
  const value = probe(real, 0x11);
  assert.equal(value, 0x07);
  assert.equal(value !== 0x00 && value !== 0xff, true);
});

test('scripted transport reproduces the app transaction sequence', () => {
  const certificate = Buffer.alloc(300, 0x5a);
  const signature = Buffer.alloc(128, 0xa5);
  const challenge = Buffer.alloc(20, 0x11);

  const transport = new ScriptedTransport([
    selectStep(0x30),
    readStep(2, Buffer.from([0x01, 0x2c])),
    selectStep(0x31),
    readStep(128, certificate.subarray(0, 128)),
    selectStep(0x32),
    readStep(128, certificate.subarray(128, 256)),
    selectStep(0x33),
    readStep(44, certificate.subarray(256)),
    writeStep(0x20, Buffer.from([0x00, 0x14])),
    writeStep(0x21, challenge),
    writeStep(0x10, Buffer.from([0x01])),
    selectStep(0x10),
    readStep(1, Buffer.from([0x10])),
    selectStep(0x11),
    readStep(2, Buffer.from([0x00, 0x80])),
    selectStep(0x12),
    readStep(128, signature),
  ]);

  const address = 0x10;
  const select = (register) => transport.transaction(address, Buffer.from([register]), 0);
  const read = (count) => transport.transaction(address, Buffer.alloc(0), count);
  const write = (register, data) => transport.transaction(
    address,
    Buffer.concat([Buffer.from([register]), Buffer.from(data)]),
    0,
  );

  select(0x30);
  assert.equal(read(2).readUInt16BE(0), 300);
  const parts = [];
  for (const [register, count] of [[0x31, 128], [0x32, 128], [0x33, 44]]) {
    select(register);
    parts.push(read(count));
  }
  assert.equal(Buffer.concat(parts).equals(certificate), true);
  write(0x20, Buffer.from([0x00, 0x14]));
  write(0x21, challenge);
  write(0x10, Buffer.from([0x01]));
  select(0x10);
  assert.equal(read(1)[0], 0x10);
  select(0x11);
  assert.equal(read(2).readUInt16BE(0), 128);
  select(0x12);
  assert.equal(read(128).equals(signature), true);
  assert.equal(transport.remaining, 0);
});
