# mfi-model

A zero-dependency Node.js model of the MFi authentication layer used by DiPlay 0.2.22.

It is a **test double**, not a licensed MFi implementation. It generates a self-signed P-256
test PKI and never reads the Apple/Carlinkit identity in the APK. It can exercise DiPlay's
remote-MFi path, the iAP2 message framing, the AirPlay MFiSAP exchange, and the coprocessor
register state machine.

## Requirements

- Node.js 24+ (verified on 26.12.1). Raw-digest P-256 ECDSA is implemented in
  `src/ecdsa.js` with BigInt arithmetic, because `crypto.sign(null, …)` with an EC key hashes the
  input on this Node release (see `spec/04-unknowns.md` §10). The model otherwise relies on the
  built-in `node:test`, `node:http`, `fetch`, X25519, and AES-128-CTR support.
- OpenSSL on `PATH` for `tools/gen-test-pki.sh`.

No npm packages are installed or required.

## Commands

```sh
npm test                 # pretest generates the PKI; node --test runs 67 cases
npm run selftest         # same checks as a single PASS/FAIL report
node src/cli.js serve    # remote MFi test service, default 127.0.0.1:8787
node src/cli.js serve --port 9000 --token secret --baa --delay 200
node src/cli.js vectors  # print iAP2 golden vectors
node src/cli.js iap2-selftest
node src/cli.js sap-selftest
node src/cli.js analyze-apk [--apk path]
```

`serve` options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--port` | `8787` | TCP port |
| `--host` | `127.0.0.1` | Bind address |
| `--token` | none | Require `Authorization: Bearer <token>` |
| `--baa` | off | Serve the BAA test identity/package |
| `--pki` | `build/test-pki` | Test PKI directory |
| `--delay` | `0` | Delay the first `/mfi/sign` request (retry test) |

## Remote API

```http
GET /mfi/certificate
200 {"protocolMajor":3,"type":"mfi","certificate":"<base64>","certificateSha256":"<hex>"}
```

`type` is omitted for MFI. For BAA it is `"baa"` and `certificate` is
`u32 leafLen | u32 intermediateLen | leaf || intermediate`.

```http
POST /mfi/sign
{"challenge":"<base64 1..128 bytes>","requestId":"<uuid>"}
200 {"signature":"<base64 64 bytes for P-256>","requestId":"<uuid>"}
```

A repeated `requestId` with the same challenge returns the cached signature; a repeated
`requestId` with a different challenge returns `409`.

```http
POST /mfi/reset
{}
200 {"detail":""}
```

Errors use `{"detail":"..."}` with a non-2xx status.

## Module map

| File | Responsibility |
| --- | --- |
| `src/bytes.js` | big-endian integers, hex/base64, range checks |
| `src/csm.js` | CSM frames, parameters, incremental decoder |
| `src/ecdsa.js` | P-256 raw-digest sign/verify, DER ↔ raw |
| `src/pki.js` | test PKI generation/loading, `TestMfiAuthenticator` |
| `src/coprocessor.js` | I2C register model and scripted transport |
| `src/iap2-auth.js` | `0xAA00`–`0xAA06` responder and codecs |
| `src/sap.js` | AirPlay MFiSAP responder and peer driver |
| `src/remote-server.js` | `/mfi/*` HTTP service |
| `src/remote-client.js` | DiPlay-compatible client |
| `src/mock-phone.js` | phone-side driver, certificate/chain checks |
| `src/cli.js` | commands |
| `src/ensure-pki.js` | pretest PKI generation |

## Test coverage

- CSM vectors, concatenation, garbage, split start markers, bounds.
- P-256 raw-digest signatures, DER/raw round-trips, negative/short digests.
- Test PKI: key/cert match, test OID present, Apple OID absent, BAA chain.
- Coprocessor: 128-byte certificate windows, challenge/signature sequence, auth delay, error
  codes, discovery with floating-bus rejection, NACK paths, scripted app sequence.
- iAP2: MFI and BAA certificate frames, `0xAA00`–`0xAA05`, malformed challenges, full exchange.
- SAP: MFI and BAA, protocol major 2 SHA-1, malformed bodies, zero shared secret, `baIC` headers.
- Remote: reset/cache/sign, stable `requestId` retry, 500 retry, token, SHA mismatch, unknown
  type, BAA, 404, cleartext-host policy.
- Negative: unrelated CA rejection, Apple marker detection on the shipped public certificate.

## Design notes

- **Signature semantics.** The model signs a 32-byte digest directly (BigInt ECDSA in
  `src/ecdsa.js`, since Node's `crypto.sign(null, …)` re-hashes with an EC key) and returns raw
  64-byte `r||s`, matching DiPlay's `NONEwithECDSA` plus
  `derToRaw`. A 20-byte SHA-1 digest is supported through `signRawDigest`/`verifyRawDigest` for
  the protocol-major-2 SAP path.
- **Test certificate.** The leaf carries a critical private OID (`1.3.6.1.4.1.55555.1` for MFI,
  `.2` for BAA) and is signed by a generated test CA. The negative suite asserts that the Apple
  marker OID (`1.2.840.113635.100.6.36`) is absent.
- **Coprocessor.** The model implements the same select/read/write transaction shapes as
  `MfiAuthenticationClient`, including the 128-byte certificate windows and the asynchronous
  auth-status poll (`signDelayMs`).
- **BAA.** The real chip's semantics for a 64-byte input are unknown; the model hashes non-32-byte
  inputs with SHA-256 and documents this as a modelled choice.

## Scope

This package is for protocol development, conformance testing, and analysis. It does not
authenticate to a real iPhone and does not include an Apple-issued identity.
