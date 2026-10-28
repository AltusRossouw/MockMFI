/**
 * In-memory model of the MFi authentication coprocessor's I2C register interface.
 *
 * The model implements the exact transactions used by DiPlay's `MfiAuthenticationClient`:
 * a one-byte register select with no read, a separate pure read, and register writes.
 */

import { u16, readU16 } from './bytes.js';

export class I2cNack extends Error {
  constructor(message = 'I2C NACK') {
    super(message);
    this.name = 'I2cNack';
  }
}

export class CoprocessorModel {
  constructor({
    authenticator,
    deviceVersion = 0x07,
    protocolMajor = 3,
    signDelayMs = 0,
    failAuth = false,
    errorCode = 0x00,
    address7Bit = null,
  }) {
    this.authenticator = authenticator;
    this.deviceVersion = deviceVersion;
    this.protocolMajorValue = protocolMajor;
    this.signDelayMs = signDelayMs;
    this.failAuth = failAuth;
    this.errorCode = errorCode;
    this.address7Bit = address7Bit;
    this.certificate = Buffer.from(authenticator.readCertificate());
    this.selected = -1;
    this.challengeLength = 0;
    this.challenge = Buffer.alloc(0);
    this.response = Buffer.alloc(0);
    this.authStatus = 0x00;
    this.readyAt = 0;
    this.error = 0;
  }

  reset() {
    this.challengeLength = 0;
    this.challenge = Buffer.alloc(0);
    this.response = Buffer.alloc(0);
    this.authStatus = 0x00;
    this.readyAt = 0;
    this.error = 0;
  }

  transaction(address7Bit, writeData, readLength) {
    if (this.address7Bit !== null && address7Bit !== this.address7Bit) {
      throw new I2cNack(`unexpected address 0x${address7Bit.toString(16)}`);
    }
    const write = Buffer.from(writeData ?? Buffer.alloc(0));
    if (write.length === 1) {
      this.selected = write[0];
      return Buffer.alloc(0);
    }
    if (write.length === 0) {
      return this.read(readLength);
    }
    this.write(write[0], write.subarray(1));
    return Buffer.alloc(0);
  }

  read(readLength) {
    if (this.selected < 0) throw new I2cNack('no register selected');
    const register = this.selected;

    switch (register) {
      case 0x00:
        if (readLength !== 1) throw new I2cNack('device version read must be one byte');
        return Buffer.from([this.deviceVersion]);
      case 0x02:
        if (readLength !== 1) throw new I2cNack('protocol major read must be one byte');
        return Buffer.from([this.protocolMajorValue]);
      case 0x05:
        if (readLength !== 1) throw new I2cNack('error register read must be one byte');
        return Buffer.from([this.error]);
      case 0x10:
        if (readLength !== 1) throw new I2cNack('auth status read must be one byte');
        this.maybeComplete();
        return Buffer.from([this.authStatus]);
      case 0x11:
        if (readLength !== 2) throw new I2cNack('response length read must be two bytes');
        return u16(this.response.length);
      case 0x12:
        return this.sliceRead(this.response, readLength, 'response');
      case 0x20:
        if (readLength !== 2) throw new I2cNack('challenge length read must be two bytes');
        return u16(this.challengeLength);
      case 0x21:
        return this.sliceRead(this.challenge, readLength, 'challenge');
      case 0x30:
        if (readLength !== 2) throw new I2cNack('certificate length read must be two bytes');
        return u16(this.certificate.length);
      default:
        break;
    }

    if (register >= 0x31 && register <= 0xff) {
      if (readLength > 128) throw new I2cNack('certificate window read exceeds 128 bytes');
      const offset = (register - 0x31) * 128;
      if (offset >= this.certificate.length) throw new I2cNack('certificate window out of range');
      return Buffer.from(this.certificate.subarray(offset, offset + readLength));
    }

    throw new I2cNack(`unreadable register 0x${register.toString(16)}`);
  }

  sliceRead(source, readLength, name) {
    if (readLength < 1 || readLength > source.length) {
      throw new I2cNack(`${name} read of ${readLength} bytes is out of range`);
    }
    return Buffer.from(source.subarray(0, readLength));
  }

  write(register, data) {
    switch (register) {
      case 0x10:
        if (data.length !== 1 || data[0] !== 0x01) throw new I2cNack('unsupported auth command');
        this.startAuthentication();
        return;
      case 0x20:
        if (data.length !== 2) throw new I2cNack('challenge length write must be two bytes');
        this.challengeLength = readU16(data, 0);
        this.challenge = Buffer.alloc(0);
        this.response = Buffer.alloc(0);
        this.authStatus = 0x00;
        this.error = 0;
        return;
      case 0x21:
        this.challenge = Buffer.concat([this.challenge, Buffer.from(data)]);
        return;
      default:
        throw new I2cNack(`unwritable register 0x${register.toString(16)}`);
    }
  }

  startAuthentication() {
    if (this.failAuth) {
      this.error = this.errorCode;
      this.authStatus = 0xff;
      return;
    }
    if (
      this.challengeLength < 1 ||
      this.challengeLength > 128 ||
      this.challenge.length !== this.challengeLength
    ) {
      this.error = 0x01;
      this.authStatus = 0xff;
      return;
    }
    try {
      this.response = Buffer.from(this.authenticator.signChallenge(this.challenge));
      this.readyAt = Date.now() + this.signDelayMs;
      this.authStatus = this.signDelayMs > 0 ? 0x00 : 0x10;
    } catch {
      this.error = 0x02;
      this.authStatus = 0xff;
    }
  }

  maybeComplete() {
    if (this.authStatus === 0x00 && Date.now() >= this.readyAt) {
      this.authStatus = 0x10;
    }
  }
}

/** One scripted I2C transaction. */
export class ScriptedTransport {
  constructor(steps) {
    this.steps = Array.from(steps);
    this.index = 0;
  }

  transaction(address7Bit, writeData, readLength) {
    if (this.index >= this.steps.length) {
      throw new Error(`unexpected transaction at index ${this.index}`);
    }
    const step = this.steps[this.index];
    if (step.address7Bit !== null && step.address7Bit !== address7Bit) {
      throw new Error(
        `address mismatch at step ${this.index}: expected 0x${step.address7Bit.toString(16)}, got 0x${address7Bit.toString(16)}`,
      );
    }
    const write = Buffer.from(writeData ?? Buffer.alloc(0));
    if (!write.equals(step.writeData)) {
      throw new Error(
        `write mismatch at step ${this.index}: expected ${step.writeData.toString('hex')}, got ${write.toString('hex')}`,
      );
    }
    if (readLength !== step.readLength) {
      throw new Error(`read length mismatch at step ${this.index}: expected ${step.readLength}, got ${readLength}`);
    }
    this.index += 1;
    return Buffer.from(step.response ?? Buffer.alloc(0));
  }

  get remaining() {
    return this.steps.length - this.index;
  }
}

export function selectStep(register, { address7Bit = null } = {}) {
  return { address7Bit, writeData: Buffer.from([register]), readLength: 0, response: Buffer.alloc(0) };
}

export function readStep(readLength, response, { address7Bit = null } = {}) {
  return { address7Bit, writeData: Buffer.alloc(0), readLength, response: Buffer.from(response) };
}

export function writeStep(register, payload, { address7Bit = null } = {}) {
  return {
    address7Bit,
    writeData: Buffer.concat([Buffer.from([register]), Buffer.from(payload)]),
    readLength: 0,
    response: Buffer.alloc(0),
  };
}
