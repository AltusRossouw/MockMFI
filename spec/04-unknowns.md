# Unknowns and bounded claims

These are recorded rather than guessed. Each entry says what is known, what is not, and how
the model behaves in the meantime.

## 1. BAA signing semantics for a 64-byte input

- **Known:** `MfiSapAuthSetup` calls `mfi.signChallenge(pair.publicKey + peerPublicKey)` for
  `MfiCertificateType.BAA` (64 bytes). The remote client accepts 1..128-byte challenges and
  forwards them unchanged. The local P-256 provider accepts only 32 bytes.
- **Unknown:** whether a real BAA coprocessor/service signs the 64-byte input directly,
  hashes it first, or applies a domain-separation step. The source does not establish it.
- **Model behavior:** the model's `signChallenge` accepts 1..128 bytes. For a 32-byte input it
  signs the raw digest (matching the MFI/P-256 path). For a 64-byte BAA input it uses
  `SHA-256(input)` and marks this as a modeled choice in `sign/` and in the test names. A
  future real-identity run must verify the actual chip behavior before relying on it.

## 2. Challenge length on real iOS versions

- **Known:** DiPlay's iAP2 responder accepts 1..128 bytes; the local signer requires exactly
  32; the AirPlay SAP path supplies 32 (MFI) or 64 (BAA) bytes.
- **Unknown:** whether every iOS version sends exactly 32 bytes in `0xAA02`. The transport is
  length-agnostic by design.
- **Model behavior:** the iAP2 responder accepts 1..128 and the signer enforces 32 for MFI;
  a non-32 challenge is a typed failure, not a silent truncation.

## 3. Coprocessor error codes and device-version semantics

- **Known:** the client reads `0x05` best-effort and includes it in
  `MfiAuthenticationFailedException`; discovery rejects device versions `0x00` and `0xFF`.
- **Unknown:** the meaning of each error code, the full device-version space, and whether
  `0x02` (protocol major) changes any register behavior. The client deliberately imposes no
  protocol-major policy on the signing sequence.
- **Model behavior:** the coprocessor model exposes an injectable error register and a
  configurable device version; tests cover `0x00`/`0xFF` rejection and a generic error code.

## 4. Trust anchor and iPhone acceptance

- **Known:** the APK ships one Apple-issued leaf certificate and its matching private key. The
  iPhone is expected to chain it to an Apple MFi trust anchor that is not in the artifact.
- **Unknown (not tested here):** whether a given iOS build accepts this identity, and which
  Apple root/chain it uses. This is a runtime/authorization question, not a static one.
- **Model behavior:** the model never presents the shipped identity. It uses a generated test
  CA/leaf, and its negative test asserts the absence of the Apple marker OID and a failed
  Apple-anchor check. Real acceptance requires an authorized Apple-issued identity.

## 5. APK-level decompilation — resolved

- **Known (2026-10-28):** with a caller-supplied JDK 21 and `jadx-headless-mcp` 0.7.1
  (`REA_JADX_MCP_JAR`), REA's Android provider decompiled the MFi layer from `classes3.dex`.
  Every constant, message id, limit and response layout in `spec/02-protocol.md` matches the
  shipped code; see `spec/05-rea-shipped-dex.md` for the evidence ids.
- **Unknown:** code outside the 147 selected MFi/iAP2/AirPlay/transport/orchestration classes
  (reflection, dynamic loading) was not decompiled.
- **Model behavior:** shipped code is now treated as authoritative; the published source
  snapshot agrees with it for this layer.

## 6. `0xAA06` and device authentication (`0xAA10`–`0xAA15`)

- **Known:** the endpoint catalog defines `AuthenticationCertificateSerial` (`0xAA06`) and the
  device-authentication endpoints (`0xAA10`–`0xAA15`; requests are accessory → phone and
  responses are phone → accessory).
- **Unknown:** whether DiPlay's CarPlay flows use `0xAA06` or the device-authentication
  direction on any iOS version; the MFi client only handles `0xAA00`–`0xAA05`.
- **Model behavior:** the model implements `0xAA00`–`0xAA05` and rejects other IDs; `0xAA06`
  and `0xAA10`–`0xAA15` are documented but not exercised.

## 7. AirPlay SAP `baIC` schema

- **Known:** `encodeBaaIntermediate` builds an OPACK object `{"baIC": intermediate}` with the
  header table reproduced in `spec/02-protocol.md`.
- **Unknown:** the full OPACK schema/versioning and whether other BAA fields are required by
  a real phone.
- **Model behavior:** the model reproduces the documented header and the raw intermediate; the
  BAA SAP path is covered for the MFI-shaped response only when a BAA authenticator is used.

## 8. Remote service internals

- **Known:** the client-side contract in `RemoteMfiAuthenticationClient` and the upstream
  endpoint table. `docs/UPSTREAM-README.md` says only BAA has been tested against a real
  remote service.
- **Unknown:** the real service's concurrency, idempotency, token policy, and whether it
  returns a `requestId`. The client ignores extra fields and retries with the same ID.
- **Model behavior:** the model server implements the documented contract, caches signatures
  per `requestId` + challenge, and offers test hooks for delay/error injection.

## 9. Timing constants are implementation choices

- **Known:** 10 ms initial auth delay, 10 ms poll, 3 s auth timeout, 2 s I/O retry, 20 ms
  retry spacing, 30 s iAP2 auth timeout, 5 s connect / 10 s read on the remote client.
- **Unknown:** the real chip's required timing; these are the app's safe bounds.
- **Model behavior:** all delays are injectable; tests use zero/short delays and assert the
  timeout paths with fake clocks or short budgets.

## 10. Node's `crypto.sign(null, …)` does not implement `NONEwithECDSA` — resolved in the model

- **Observed (Node 26.12.1, macOS arm64):** a signature produced by
  `crypto.sign(null, digest, { key: ecKey, dsaEncoding: 'ieee-p1363' })` verifies in OpenSSL
  against `SHA-256(digest)`, not against `digest`. With an EC key this Node release routes the
  input through the key's default digest, so the "raw digest" call actually hashes again.
  `crypto.verify(null, …)` behaves the same way.
- **Impact before the fix:** the Node model's signatures were over a re-hashed value. Its own
  tests passed because sign and verify shared the mistake, but a real phone would have rejected
  them, and the model could not validate signatures from the C library.
- **Fix:** `mfi-model/src/ecdsa.js` now implements P-256 ECDSA over BigInt (affine points,
  double-and-add, RFC 6979-free random `k`) and signs/verifies the digest exactly as supplied.
  Bidirectional agreement with OpenSSL is checked by `tools/crosscheck-mfid.mjs` and by
  `mfid verify`.
- **Model behavior:** the model and `libmfi` now agree byte for byte; `npm test` (67 tests) and
  the C suite both pass against the same identities.

## 11. What this project does not claim

- It does not claim that the shipped identity is authorized for DiPlay or for redistribution.
- It does not claim that the model can authenticate to a real iPhone.
- It does not claim that the source and APK are byte-identical at the method level.
- It does not provide, derive, or use the Apple/Carlinkit private key.
