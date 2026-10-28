#!/usr/bin/env python3
"""Client for the LIVI "mfid" MFi coprocessor protocol, used to test `mfid net`.

Mirrors LIVI's native/crates/iap2-mfi/src/ncm.rs:
  request   1 byte op | for SIGN: u16 BE length | challenge
  response  1 byte status (0 ok, 1 error) | u16 BE length | payload

Usage: livi-mfid-client.py HOST PORT [--verify-bin PATH --identity DIR]
"""
import argparse
import socket
import subprocess
import sys

OP_GET_CERT = 0x01
OP_SIGN = 0x02
OP_PROTOCOL_MAJOR = 0x03
STATUS_OK = 0


class MfidError(RuntimeError):
    pass


class MfidClient:
    def __init__(self, host, port, timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def close(self):
        self.sock.close()

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise MfidError("connection closed")
            buf += chunk
        return buf

    def request(self, req):
        self.sock.sendall(req)
        header = self._read_exact(3)
        status = header[0]
        length = (header[1] << 8) | header[2]
        data = self._read_exact(length) if length else b""
        if status != STATUS_OK:
            raise MfidError(f"status {status}")
        return data

    def protocol_major(self):
        return self.request(bytes([OP_PROTOCOL_MAJOR]))[0]

    def certificate(self):
        return self.request(bytes([OP_GET_CERT]))

    def sign(self, challenge):
        if not 1 <= len(challenge) <= 128:
            raise ValueError("challenge must be 1..128 bytes")
        req = bytes([OP_SIGN, (len(challenge) >> 8) & 0xFF, len(challenge) & 0xFF]) + challenge
        return self.request(req)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--verify-bin")
    ap.add_argument("--identity")
    args = ap.parse_args()

    failures = 0

    def check(ok, label, extra=""):
        nonlocal failures
        print(f"{'ok  ' if ok else 'FAIL'} {label}{(' ' + extra) if extra else ''}")
        if not ok:
            failures += 1

    client = MfidClient(args.host, args.port)
    digest = bytes(range(32))

    major = client.protocol_major()
    check(major == 3, "protocol major is 3", f"(got {major})")

    cert = client.certificate()
    check(len(cert) > 100 and cert[0] == 0x30, "certificate is a DER container", f"({len(cert)} bytes)")

    signature = client.sign(digest)
    check(len(signature) == 64, "signature is 64 raw bytes")

    if args.verify_bin and args.identity:
        rc = subprocess.run(
            [args.verify_bin, "--identity", args.identity, "verify", digest.hex(), signature.hex()],
            capture_output=True,
            text=True,
        )
        check(rc.returncode == 0, "signature verifies with the identity key", rc.stdout.strip())

    client.close()
    print(f"\n{'FAILED' if failures else 'PASS'} ({failures} failure{'s' if failures != 1 else ''})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
