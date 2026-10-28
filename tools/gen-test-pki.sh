#!/usr/bin/env bash
# Generate a self-contained P-256 test PKI for the MockMFI model.
#
# The output is TEST MATERIAL ONLY. It is not Apple-issued, it does not contain Apple OIDs, and
# it must never be used to authenticate to a real device.
#
# Layout (written to <dir>):
#   ca.key ca.crt ca.der                  test root CA
#   leaf.key leaf.crt leaf.der leaf.p7b   MFI-style test leaf
#   leaf.pk8                              PKCS#8 DER private key for the leaf
#   int.key int.crt int.der               BAA test intermediate
#   baa_leaf.key baa_leaf.crt baa_leaf.der
#   baa_leaf.pk8
#
# Usage: tools/gen-test-pki.sh <output-dir>
set -euo pipefail

dir="${1:?usage: gen-test-pki.sh <output-dir>}"
command -v openssl >/dev/null 2>&1 || { echo "missing tool: openssl" >&2; exit 2; }
mkdir -p "$dir"
umask 077

gen_key() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$1"
}

# --- root CA -------------------------------------------------------------------------------
gen_key "$dir/ca.key"
openssl req -x509 -new -key "$dir/ca.key" -sha256 -days 3650 \
  -subj "/O=MockMFI Test/CN=MockMFI Test Root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out "$dir/ca.crt"
openssl x509 -in "$dir/ca.crt" -outform DER -out "$dir/ca.der"

# --- MFI-style test leaf -------------------------------------------------------------------
gen_key "$dir/leaf.key"
openssl req -new -key "$dir/leaf.key" \
  -subj "/O=MockMFI Test/CN=MockMFI Test Accessory" \
  -out "$dir/leaf.csr"
cat >"$dir/leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
1.3.6.1.4.1.55555.1=critical,ASN1:UTF8String:mockmfi-test
EOF
openssl x509 -req -in "$dir/leaf.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAserial "$dir/root.srl" -CAcreateserial -days 3650 -sha256 \
  -extfile "$dir/leaf.ext" -out "$dir/leaf.crt"
openssl x509 -in "$dir/leaf.crt" -outform DER -out "$dir/leaf.der"
openssl pkcs8 -topk8 -nocrypt -in "$dir/leaf.key" -outform DER -out "$dir/leaf.pk8"
openssl crl2pkcs7 -nocrl -certfile "$dir/leaf.crt" -outform DER -out "$dir/leaf.p7b"

# --- BAA intermediate + leaf ---------------------------------------------------------------
gen_key "$dir/int.key"
openssl req -new -key "$dir/int.key" \
  -subj "/O=MockMFI Test/CN=MockMFI Test Intermediate" \
  -out "$dir/int.csr"
cat >"$dir/int.ext" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in "$dir/int.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAserial "$dir/root.srl" -days 3650 -sha256 \
  -extfile "$dir/int.ext" -out "$dir/int.crt"
openssl x509 -in "$dir/int.crt" -outform DER -out "$dir/int.der"

gen_key "$dir/baa_leaf.key"
openssl req -new -key "$dir/baa_leaf.key" \
  -subj "/O=MockMFI Test/CN=MockMFI Test BAA Accessory" \
  -out "$dir/baa_leaf.csr"
cat >"$dir/baa_leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
1.3.6.1.4.1.55555.2=critical,ASN1:UTF8String:mockmfi-baa-test
EOF
openssl x509 -req -in "$dir/baa_leaf.csr" -CA "$dir/int.crt" -CAkey "$dir/int.key" \
  -CAserial "$dir/int.srl" -CAcreateserial -days 3650 -sha256 \
  -extfile "$dir/baa_leaf.ext" -out "$dir/baa_leaf.crt"
openssl x509 -in "$dir/baa_leaf.crt" -outform DER -out "$dir/baa_leaf.der"
openssl pkcs8 -topk8 -nocrypt -in "$dir/baa_leaf.key" -outform DER -out "$dir/baa_leaf.pk8"

# Remove CSRs and extension files; keep the keys, certs and DER fixtures.
rm -f "$dir"/*.csr "$dir"/*.ext

echo "generated test PKI in $dir"
