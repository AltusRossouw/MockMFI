#!/usr/bin/env bash
# Read-only profile of the MFi identity shipped in a DiPlay APK.
#
# Prints the public certificate profile and whether the PKCS#8 private key matches the
# certificate's public key. It NEVER prints, copies, or persists private-key material: the
# key is written only to a mode-700 mktemp directory and removed by the EXIT trap.
#
# Usage: tools/analyze-apk-identity.sh [APK]
set -euo pipefail

apk="${1:-DiPlay-0.2.22.apk}"
if [[ ! -f "$apk" ]]; then
  echo "APK not found: $apk" >&2
  exit 2
fi
for tool in unzip openssl cmp sed grep; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 2; }
done

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
chmod 700 "$tmp"

unzip -p "$apk" assets/offline-mfi/certificate.p7b >"$tmp/cert.p7b"
unzip -p "$apk" assets/offline-mfi/identity.pk8 >"$tmp/id.pk8"
chmod 600 "$tmp/id.pk8" "$tmp/cert.p7b"

# Isolate the single PEM certificate from the PKCS#7 bundle.
openssl pkcs7 -inform DER -in "$tmp/cert.p7b" -print_certs -out "$tmp/certs.pem" >/dev/null 2>&1
sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$tmp/certs.pem" >"$tmp/cert.pem"
count="$(grep -c 'BEGIN CERTIFICATE' "$tmp/cert.pem" || true)"
if [[ "$count" -ne 1 ]]; then
  echo "expected exactly one certificate, found $count" >&2
  exit 1
fi

echo "== certificate =="
openssl x509 -in "$tmp/cert.pem" -noout -subject -issuer -serial -dates -fingerprint -sha256
echo
echo "== public key =="
openssl x509 -in "$tmp/cert.pem" -noout -text \
  | sed -n '/Public Key Algorithm/,/ASN1 OID/p'
echo
echo "== Apple MFi marker 1.2.840.113635.100.6.36 =="
if openssl x509 -in "$tmp/cert.pem" -noout -text | grep -q '1\.2\.840\.113635\.100\.6\.36'; then
  echo "present (critical)"
else
  echo "absent"
fi

# Compare the private key's public half with the certificate. Only public material leaves
# this directory.
openssl pkey -inform DER -in "$tmp/id.pk8" -pubout -outform DER -out "$tmp/id.pub.der" 2>/dev/null
openssl x509 -in "$tmp/cert.pem" -pubkey -noout \
  | openssl pkey -pubin -outform DER -out "$tmp/cert.pub.der" 2>/dev/null

echo
echo "== key/certificate consistency =="
if cmp -s "$tmp/id.pub.der" "$tmp/cert.pub.der"; then
  echo "key-cert-match: yes"
else
  echo "key-cert-match: NO" >&2
  exit 1
fi

echo
echo "note: this script profiles public material only; it does not sign, export, or print the private key."
