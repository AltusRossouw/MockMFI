#!/usr/bin/env python3
"""Profile the MFi identity inside a dongle image, a firmware dump or an identity directory.

HUDIY's CarPlay runs through a CarlinKit CPC200-CCPA / CPC200-Autokit dongle; that dongle,
not HUDIY, is the MFi accessory and carries the certificate the iPhone authenticates. This
tool tells you which identity a dongle image (or any extracted directory) actually holds:

  * certificate subject / issuer / serial / SHA-256 / validity
  * the Apple MFi marker extension 1.2.840.113635.100.6.36
  * whether the private key in the image matches the certificate

It prints public data only and never emits key material.

Usage:
  dongle-mfi-profile.py PATH...

PATH may be a directory in the identity layout (identity.pk8 + certificate.p7b), a single
certificate or key file, a tar/zip archive, or a raw firmware blob (certificates and PKCS#8
keys are located by scanning).
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

APPLE_MFI_OID = "1.2.840.113635.100.6.36"
CERT_SUFFIXES = (".p7b", ".p7c", ".der", ".crt", ".cer", ".pem")
KEY_SUFFIXES = (".pk8", ".key", ".p8")


def run(args, data=None):
    return subprocess.run(args, input=data, capture_output=True)


def der_tlv(buf, offset):
    """Bounds of a DER SEQUENCE at offset: (start, end), or None."""
    if offset + 2 > len(buf) or buf[offset] != 0x30:
        return None
    first = buf[offset + 1]
    if first < 0x80:
        length, header = first, 2
    else:
        count = first & 0x7F
        if count == 0 or count > 3 or offset + 2 + count > len(buf):
            return None
        length = int.from_bytes(buf[offset + 2 : offset + 2 + count], "big")
        header = 2 + count
    start = offset + header
    if length <= 0 or start + length > len(buf):
        return None
    return offset, start + length


def scan_sequences(buf, minimum=200, limit=6000):
    """Yield distinct DER SEQUENCE slices that could be certificates or keys."""
    seen = set()
    attempts = 0
    offset = 0
    while offset < len(buf) - 8 and attempts < limit:
        if buf[offset] == 0x30:
            bounds = der_tlv(buf, offset)
            if bounds:
                start, end = bounds
                if end - start >= minimum:
                    blob = bytes(buf[start:end])
                    if blob not in seen:
                        seen.add(blob)
                        attempts += 1
                        yield blob
        offset += 1


def pem_certificate(data):
    """Convert DER PKCS#7, DER certificate or PEM into PEM certificates."""
    if data.lstrip().startswith(b"-----BEGIN"):
        certs = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
        return b"\n".join(certs) + b"\n" if certs else None
    pkcs7 = run(["openssl", "pkcs7", "-inform", "DER", "-print_certs", "-outform", "PEM"], data)
    if pkcs7.returncode == 0 and b"BEGIN CERTIFICATE" in pkcs7.stdout:
        return pkcs7.stdout
    x509 = run(["openssl", "x509", "-inform", "DER", "-outform", "PEM"], data)
    if x509.returncode == 0 and b"BEGIN CERTIFICATE" in x509.stdout:
        return x509.stdout
    return None


def key_public_der(data):
    for inform in ("DER", "PEM"):
        result = run(["openssl", "pkey", "-inform", inform, "-pubout", "-outform", "DER"], data)
        if result.returncode == 0 and result.stdout:
            return result.stdout
    return None


def describe(pem_block):
    """Yield one dict per certificate in the PEM block."""
    parts = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_block, re.S)
    for pem in parts:
        pem += b"\n"
        text = run(["openssl", "x509", "-noout", "-text"], pem)
        if text.returncode != 0:
            continue
        body = text.stdout.decode("utf-8", "replace")
        facts = {"_pem": pem, "apple_marker": APPLE_MFI_OID in body}

        summary = run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-serial", "-enddate", "-fingerprint", "-sha256"],
            pem,
        )
        for line in summary.stdout.decode("utf-8", "replace").splitlines():
            if line.startswith("subject="):
                facts["subject"] = line[len("subject=") :].strip()
            elif line.startswith("issuer="):
                facts["issuer"] = line[len("issuer=") :].strip()
            elif line.startswith("serial="):
                facts["serial"] = line[len("serial=") :].strip()
            elif line.startswith("notAfter="):
                facts["not_after"] = line[len("notAfter=") :].strip()
            elif "Fingerprint=" in line:
                facts["sha256"] = line.split("=", 1)[1].replace(":", "").lower()
        yield facts


def identity_dirs(root):
    """Directories that look like an MFi identity directory."""
    for current, _dirs, names in os.walk(root):
        lowered = {name.lower() for name in names}
        if "identity.pk8" in lowered or "certificate.p7b" in lowered:
            yield current


def load_dir(path):
    cert = key = None
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue
        with open(full, "rb") as handle:
            data = handle.read()
        if name.endswith(CERT_SUFFIXES):
            cert = data
        elif name.endswith(KEY_SUFFIXES):
            key = data
    if cert is None:
        return None, None
    return pem_certificate(cert), key


def gather(path):
    """Yield (description, pem_block, key_bytes_or_None)."""
    if os.path.isdir(path):
        pem, key = load_dir(path)
        if pem:
            yield path, pem, key
        for found in identity_dirs(path):
            if found == path:
                continue
            pem, key = load_dir(found)
            if pem:
                yield found, pem, key
        return

    if not os.path.isfile(path):
        print(f"  not found: {path}", file=sys.stderr)
        return

    if zipfile.is_zipfile(path) or tarfile.is_tarfile(path):
        unpacked = tempfile.mkdtemp(prefix="mfi-profile-")
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    archive.extractall(unpacked)
            else:
                with tarfile.open(path) as archive:
                    try:
                        archive.extractall(unpacked, filter="data")
                    except TypeError:  # Python < 3.12
                        archive.extractall(unpacked)
            yield from gather(unpacked)
        finally:
            shutil.rmtree(unpacked, ignore_errors=True)
        return

    with open(path, "rb") as handle:
        blob = handle.read()

    pem = pem_certificate(blob)
    if pem:
        key = None
        match = re.search(rb"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", blob, re.S)
        if match:
            key = match.group(0)
        else:
            for candidate in scan_sequences(blob, minimum=60):
                if key_public_der(candidate):
                    key = candidate
                    break
        yield path, pem, key
        return

    keys = [candidate for candidate in scan_sequences(blob, minimum=60) if key_public_der(candidate)]
    seen = set()
    for index, candidate in enumerate(scan_sequences(blob)):
        pem = pem_certificate(candidate)
        if not pem or pem in seen:
            continue
        seen.add(pem)
        yield f"{path}#candidate{index}", pem, keys[0] if keys else None


def main():
    parser = argparse.ArgumentParser(description="Profile the MFi identity in a dongle image or directory")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()

    if not shutil.which("openssl"):
        print("openssl not found on PATH", file=sys.stderr)
        return 2

    total = 0
    mismatched = 0
    for path in args.paths:
        print(f"== {path}")
        found_any = False
        for label, pem_block, key in gather(path):
            for facts in describe(pem_block):
                found_any = True
                total += 1
                print(f"  source:  {label}")
                print(f"  subject: {facts.get('subject', '?')}")
                print(f"  issuer:  {facts.get('issuer', '?')}")
                print(f"  serial:  {facts.get('serial', '?')}")
                print(f"  sha256:  {facts.get('sha256', '?')}")
                if facts.get("not_after"):
                    print(f"  valid until: {facts['not_after']}")
                print(
                    f"  apple mfi marker ({APPLE_MFI_OID}): "
                    f"{'present' if facts['apple_marker'] else 'absent'}"
                )
                if key:
                    cert_pub = run(["openssl", "x509", "-noout", "-pubkey"], facts["_pem"]).stdout
                    cert_der = run(["openssl", "pkey", "-pubin", "-outform", "DER"], cert_pub).stdout
                    key_der = key_public_der(key)
                    if cert_der and key_der:
                        if cert_der == key_der:
                            print("  key matches certificate: yes")
                        else:
                            print("  key matches certificate: NO")
                            mismatched += 1
                    else:
                        print("  key matches certificate: unknown (unreadable key)")
                else:
                    print("  key matches certificate: no key in this input")
                print()
        if not found_any:
            print("  no MFi identity found\n")

    print(f"{total} identit{'y' if total == 1 else 'ies'} profiled, {mismatched} key mismatch(es)")
    return 0 if total and mismatched == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
