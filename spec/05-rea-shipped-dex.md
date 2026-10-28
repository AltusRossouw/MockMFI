# Shipped-DEX decompilation (REA + JADX)

This document replaces the earlier limitation in `01-artifact-and-identity.md` §7 ("no APK-level
decompilation was performed"). The MFi layer in `DiPlay-0.2.22.apk` was decompiled from
`classes3.dex` with REA's Android (JADX) provider, and every protocol claim in `02-protocol.md`
was re-checked against that decompiled shipped code rather than the published source snapshot.

## 1. Tooling

REA 6.8.0 (`rea-agents`) with `jdk` 21.0.13 + `jadx-headless-mcp` 0.7.1:

```sh
export JAVA_HOME=/path/to/jdk-21
export REA_JADX_MCP_JAR=/path/to/jadx-headless-mcp-0.7.1-all.jar
npx -y rea-agents@6.8.0 doctor --provider jadx --json     # healthy
```

The diagram below is the route that was actually used:

```
APK --open_binary/inspect_artifact--> archive graph (360 entries, 304 nodes, APK SHA-256 7d04db26…)
    --inspect_android_package (jadx 0.7.1)--> manifest, 30 621 classes
    --inspect_android_class / -method--> evidence per class/method
    --DecompileApk (jadx.api, same engine)--> 147 selected classes as Java
```

Provider identity for every Android result: `jadx` 0.7.1 (engine artifact SHA-256
`6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75`, source revision
`5844800a486d2248fa949b74c9896285f5b54de2`, heap 6 GiB). Engine load reported
`Loaded classes: 30621, methods: 193307, instructions: 5629041`.

## 2. Evidence index

| What | Evidence |
| --- | --- |
| Package/manifest, class inventory | `ev_423c07ae7dcdf0dc155fb356d2f55f99e74c25c40e3c4c1ec2bbf7d99806255e` (`inspect_android_package`, summary) |
| Archive inventory (unpack) | `ev_315e53a4ae07fbef25c7aa09351de6049e3c3b161424c49e01f56a4340b48086` |
| `MfiSapAuthSetup` members | `ev_715f0cd99281009253cc72e5f619991516b02d82870e90d9fe6e65c79ed0f2e0` |
| `MfiSapAuthSetup.handle` body | `ev_58e66550def55c25dfe72d6590d1b6b65f319e85c24019f6ca3dbe9d02096c59` |
| `MfiAuthenticationClient` members | `ev_0c8feb5479b7853f72e8a69f9c9a88eb65e031f503c3efe2e10b7e5544f4ab1d` |
| `MfiAuthenticationClient.readCertificate` | `ev_56f5fc2fb107950c7e2dcf02190b2b545e9008b9e14ba7dbfe36f11487a125a7` |
| `MfiAuthenticationClient.signChallenge` | `ev_ff972282fce4d19b0b16e3b77150783193ce90604754439b01553e99aa13cf24` |
| `Iap2MfiAuthenticationClient` members | `ev_597dde17f073f31feedb8e0680ff99545e28d6cca2ba7d83eaa22d8d15665d8c` |
| `Iap2MfiAuthenticationClient.run` | `ev_7a46fcfddf7a3f4da09aa5ca44416b344284e0ae0eef24a8694745292cc6147e` |
| `Iap2AuthenticationMessages` members | `ev_dcdea73e04404f88c181a4c60d47a4ebb90ca871f21dff7fbf61d414bbcc5cbe` |
| `LocalMfiAuthenticationClient` members | `ev_ac544720182743d4032c2aaa1d082fa48e2c8e8444be811791a7fb012acfcb17` |

Local copies of the records live in `out/rea/classes/*.json` and `out/rea/methods/*.json`; the
decompiled text lives in `build/decompiled/java/` (generated, not committed).

Reproduce the decompilation:

```sh
export JAVA_HOME=... REA_JADX_MCP_JAR=...
tools/rea-decompile-apk.sh build/decompiled          # REA CLI per method
# or, one JADX engine load for a whole package (same engine, faster):
javac -cp "$REA_JADX_MCP_JAR" -d build/jadx-tool tools/DecompileApk.java
java -Xmx6g -cp "$REA_JADX_MCP_JAR":build/jadx-tool DecompileApk \
     DiPlay-0.2.22.apk build/decompiled/java com.shilapi.xcertplay.mfi com.shilapi.xcertplay.iap2 \
     com.shilapi.xcertplay.airplay com.shilapi.xcertplay.transport com.shilapi.xcertplay.orchestration
```

## 3. What the shipped code confirms

Line numbers below refer to the generated files under `build/decompiled/java/`.

### 3.1 Authenticator contract

`mfi/MfiAuthenticator.java:8` — interface with `protocolMajor(): int`,
`readCertificate(int): byte[]` (default parameter 65 525 at line 45), `signChallenge(byte[]):
byte[]`, `getCertificateType()` defaulting to `MFI` (line 66-69), and `baaCertificates()` whose
default implementation throws `"Authenticator does not provide BAA certificates"` (line 56-64).

### 3.2 Local software identity

`mfi/LocalMfiAuthenticationClient.java`

- `DIRECTORY = "offline-mfi"`, `MAX_FILE_BYTES = 16384` (lines 10-11).
- `Companion.load` (line 163) reads `identity.pk8` and `certificate.p7b`, builds the key with
  `KeyFactory.getInstance("EC")`, and fails closed when key and certificate disagree.
- `protocolMajor()` returns 3 (line 322).
- `readCertificate` returns the container bytes (line 329), i.e. the whole PKCS#7 blob — the
  accessory presents 607 bytes, not just the leaf.
- `signChallenge` requires exactly 32 bytes, signs with `NONEwithECDSA` (line 349) and converts
  DER to raw `r||s` with `derToRaw` (line 101): integer signum must be > 0, bit length ≤ 256,
  a 33-byte value is accepted only when its leading byte is 0x00, and each integer is
  right-aligned into a 32-byte field.

### 3.3 Coprocessor register driver

`mfi/MfiAuthenticationClient.java`

| Constant | Value | Line |
| --- | --- | --- |
| `PROTOCOL_MAJOR_REGISTER` | 0x02 | 33 |
| `ERROR_REGISTER` | 0x05 | 23 |
| `AUTH_CONTROL_STATUS_REGISTER` | 0x10 | 9 |
| `AUTH_START_COMMAND` / `AUTH_SUCCESS_STATUS` | 0x01 / 0x10 | 11-12 |
| `RESPONSE_LENGTH_REGISTER` / `RESPONSE_DATA_REGISTER` | 0x11 / 0x12 | 34-35 |
| `CHALLENGE_LENGTH_REGISTER` / `CHALLENGE_DATA_REGISTER` | 0x20 / 0x21 | 18-19 |
| `CERTIFICATE_LENGTH_REGISTER` / `CERTIFICATE_DATA_REGISTER` | 0x30 / 0x31 | 15-16 |
| `CERTIFICATE_REGISTER_WINDOW_BYTES` | 128 | 17 |
| `IO_RETRY_TIMEOUT_MILLIS` / `IO_RETRY_DELAY_MICROS` | 2000 / 20 000 | 26-25 |
| `AUTH_TIMEOUT_MILLIS` / `AUTH_POLL_MILLIS` / `INITIAL_AUTH_DELAY_MILLIS` | 3000 / 10 / 10 | 13, 10, 24 |
| `MAXIMUM_CHALLENGE_BYTES` | 128 | 27 |

- `readCertificate` (line 466): reads the u16 at 0x30, requires `1..maximumOutputLength`, then
  walks 0x31 + offset/128 reading `min(128, remaining)`.
- `signChallenge` (line 529): length at 0x20, data at 0x21, `0x01` at 0x10, 10 ms sleep, poll
  0x10 every 10 ms until 0x10 or 3 s; on timeout reads 0x05 best effort
  (`bestEffortErrorCode`, line 88); response length at 0x11, data at 0x12.
- `retryIo` (line 220) retries the *whole* select/read pair for 2 000 ms at 20 ms because a
  retried read alone would return the stale register.

### 3.4 iAP2 AccAuthentication responder

`mfi/Iap2MfiAuthenticationClient.java`

- Message ids: `0xAA00` 43 520, `0xAA01` 43 521, `0xAA02` 43 522, `0xAA03` 43 523, `0xAA04`
  43 524, `0xAA05` 43 525 (lines 9-19); certificate limit 65 525; challenge limit 128;
  timeout default 30 000 ms, max 300 000 ms.
- `run` (line 187): reads the certificate **once** before the loop (line 202), builds the
  certificate frame per `certificateType` (MFI: `accessoryCertificate`, BAA:
  `accessoryCertificateBody` on the raw package body), logs
  `mfi type=… certificate loaded bytes=… payload bytes=…`, then switches on the message id
  (line 250): `0xAA00` → send certificate, `0xAA02` → challenge from parameter 0, require
  `1..128`, sign, send `0xAA03`, `0xAA05` → return, `0xAA04` → throw, anything else → throw
  `"Unexpected iAP2 MFi message 0x…"`. Remaining budget is recomputed for every send/recv.

### 3.5 AirPlay `/auth-setup`

`airplay/MfiSapAuthSetup.java`

- `handle` (line 299) accepts only `len == 33` with `body[0] == 1`, generates an X25519 pair,
  rejects an all-zero shared secret (line 322-329), derives
  `aesKey = SHA-1("AES-KEY" || shared)[0..16]` and `aesIv = SHA-1("AES-IV" || shared)[0..16]`
  (lines 331-344).
- MFI branch (line 367): `readCertificate(default 65 525)`, digest =
  `protocolMajor == 2 ? SHA-1(pub || peer) : SHA-256(pub || peer)` (lines 369-379), sign,
  AES-128-CTR the signature, then `buildMfiResponse` (line 109):
  `pub(32) | u32 certLen | cert | u32 encLen | enc`.
- BAA branch (line 352): signs `pub || peer` (64 bytes) directly, AES-CTR, and appends the
  OPACK `baIC` object from `encodeBaaIntermediate` (line 160).
- `AirPlaySession` dispatches the path at line 914 and answers
  `application/octet-stream` with the handler body; a `null` result produces an empty response
  with status **400** (status constant at line 772).

### 3.6 Linux I2C transport

`transport/LinuxI2cTransport.java` opens only `/dev/i2c-[0-9]+`, validates
`0 < address7 < 0x80`, requires one of write/read, caps a message at 65 535 bytes, and maps the
native errors to `I2C remote NACK`, `I2C transaction timed out`, `I2C permission denied`.
`transport/NativeLinuxI2cBridge.java` loads `xcertplay_i2c` and calls
`open/transaction/close` — the JNI library exports exactly those three symbols
(`spec/01-artifact-and-identity.md` §6). Nothing cryptographic is native; the JNI layer is just
`ioctl`.

### 3.7 Runtime wiring

- `orchestration/MfiTarget.java` — `LOCAL`, `USB_CH341`, `I2C`, `REMOTE`.
- `orchestration/MfiRuntime.java` — discovery with a 15 000 ms probe window, then a
  `MfiAuthenticationClient` at the discovered address; no responder means
  `MfiCoprocessorNotFoundException` listing per-address failures.

## 4. Differences from the source snapshot

None found in the authentication layer: constants, limits, message ids, framing, digest choice,
response layouts and the register map match `DiPlay-main/` line for line. The decompiled code is
the authority for the module in `mfi-linux/`.

## 5. Remaining unknowns

- `CertificateFactory.generateCertificates` behaviour on a 607-byte container is a platform
  detail; the module parses the PKCS#7 itself and falls back to an X.509 scan.
- BAA signing semantics for a 64-byte input remain modelled, not observed against a real BAA
  identity (no BAA identity is present in the APK).
- Reflection, dynamic loading and code outside the selected packages were not decompiled; the
  147-class selection covers every MFi, iAP2, AirPlay, transport and orchestration class that
  touches authentication.
