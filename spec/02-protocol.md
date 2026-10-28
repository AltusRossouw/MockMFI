# MFi authentication protocol in DiPlay 0.2.22

This document describes the authentication layer as implemented by the shipped app. It is
derived from the source snapshot and confirmed against the APK where noted. No Apple private
key material is used or reproduced.

## 1. Layer map

```
                    iPhone / CarPlay controller
                              |
          iAP2 CSM frames (0x4040) with AccAuthentication 0xAA00..0xAA06
                              |
                 +------------+-------------+
                 |                          |
        /auth-setup MFiSAP          iAP2 AccAuthentication
        (AirPlay control channel)   (iAP2 control session)
                 |                          |
                 +------------+-------------+
                              |
                     MfiAuthenticator
             +----------------+----------------+
             |                |                |
      Local P-256      Coprocessor (I2C)   Remote HTTP
      (protocolMajor 3) (0xAA register map) (/mfi/certificate,
             |                |              /mfi/sign, /mfi/reset)
             +----------------+----------------+
                              |
                    Apple-issued MFi identity
                    (certificate + private key)
```

The same `MfiAuthenticator` contract (`protocolMajor()`, `readCertificate()`,
`signChallenge()`, `certificateType`, optional `baaCertificates()`) is used by both the iAP2
and AirPlay authentication paths.

## 2. iAP2 CSM framing

Source: `shared/src/main/java/com/shilapi/xcertplay/iap2/wire/Iap2CsmFramer.kt`.

```
CSM frame  = 0x4040 | u16 length | u16 messageId | body
body       = parameter*
parameter  = u16 length | u16 parameterId | payload
```

- Big-endian, no checksum.
- `length` includes the 6-byte header; minimum 6; maximum 65,535.
- The parser tolerates garbage before `0x4040`, concatenated frames, and arbitrary chunking.
- `Iap2CsmFramer.encodeFrame(messageId, payload)` and `encodeParam(id, payload)` produce bytes.

## 3. AccAuthentication state machine (accessory side)

Source: `shared/src/main/java/com/shilapi/xcertplay/mfi/Iap2MfiAuthenticationClient.kt`,
`shared/src/main/java/com/shilapi/xcertplay/iap2/message/Iap2Messages.kt` (object
`Iap2AuthenticationMessages`), `shared/src/main/java/com/shilapi/xcertplay/iap2/catalog/Iap2Endpoint.kt`
(lines 179-218).

| ID | Name | Direction | Parameters |
| --- | --- | --- | --- |
| `0xAA00` | `RequestAuthenticationCertificate` | phone → accessory | none |
| `0xAA01` | `AuthenticationCertificate` | accessory → phone | 0: certificate bytes (`MFI`); for `BAA`, 0: leaf, 1: u8 `1`, 2: intermediate |
| `0xAA02` | `RequestAuthenticationChallengeResponse` | phone → accessory | 0: challenge (1..128 bytes) |
| `0xAA03` | `AuthenticationResponse` | accessory → phone | 0: signature bytes |
| `0xAA04` | `AuthenticationFailed` | phone → accessory | none |
| `0xAA05` | `AuthenticationSucceeded` | phone → accessory | none |
| `0xAA06` | `AuthenticationCertificateSerial` | accessory → phone | not used by DiPlay |

Accessory loop (`Iap2MfiAuthenticationClient.run`):

1. Read the certificate once from the authenticator (default max 65,525 bytes).
2. Receive a frame:
   - `0xAA00` → send `0xAA01` with the certificate.
   - `0xAA02` → read parameter 0 as the challenge; require 1..128 bytes; sign; send `0xAA03`
     with parameter 0 = signature.
   - `0xAA05` → success; return.
   - `0xAA04` → throw `Iap2MfiAuthenticationException`.
   - anything else → throw.
3. Overall deadline default 30,000 ms, max 300,000 ms; every `send`/`recv` consumes the
   remaining budget. A frame that arrives after the deadline is a timeout failure.

The app's `BAA` variant (`Iap2AuthenticationMessages.baaCertificatePackage`) builds the
`0xAA01` body directly as raw parameter bytes: `param 0 = leaf`, `param 1 = 0x01`,
`param 2 = intermediate`.

## 4. AirPlay `/auth-setup` MFiSAP (accessory side)

Source: `shared/src/main/java/com/shilapi/xcertplay/airplay/MfiSapAuthSetup.kt`.

Request body (from the phone): `[version = 0x01][32-byte X25519 public key]`.
A body with a different length or version returns `null` (no response).

Accessory processing:

```
pair        = X25519 ephemeral key pair          (32-byte raw public key)
shared      = X25519(pair.private, peerPublic)
if shared is all zero: reject

aesKey = SHA-1("AES-KEY" || shared)[0..16]
aesIv  = SHA-1("AES-IV"  || shared)[0..16]

if certificateType == MFI:
    digest = protocolMajor == 2
        ? SHA-1(pair.public || peerPublic)
        : SHA-256(pair.public || peerPublic)
    signature = signChallenge(digest)             # 32-byte digest for P-256
    encrypted = AES-128-CTR(aesKey, aesIv, signature)
    response  = pair.public (32)
              || u32 certificate.size
              || certificate
              || u32 encrypted.size
              || encrypted

if certificateType == BAA:
    signature = signChallenge(pair.public || peerPublic)   # 64-byte input
    encrypted = AES-128-CTR(aesKey, aesIv, signature)
    response  = pair.public (32)
              || u32 leaf.size
              || leaf
              || u32 encrypted.size
              || encrypted
              || u32 baicBlob.size
              || baicBlob
```

`baicBlob` is an OPACK object `{"baIC": intermediate}` built by
`encodeBaaIntermediate`:

| Intermediate length | Header |
| --- | --- |
| ≤ 0x20 | `E1 44 'b' 'a' 'I' 'C' (0x70 + len)` |
| ≤ 0xFF | `E1 44 'b' 'a' 'I' 'C' 91 len` |
| ≤ 0xFFFF | `E1 44 'b' 'a' 'I' 'C' 92 len lo len hi` |
| larger | `E1 44 'b' 'a' 'I' 'C' 93 len0 len1 len2 len3` |

All multi-byte lengths are big-endian. The `u32` fields are big-endian.

## 5. Coprocessor register model (I2C / CH341)

Source: `shared/src/main/java/com/shilapi/xcertplay/mfi/MfiAuthenticationClient.kt`
(register constants at lines 227-238) and `MfiDeviceScanner.kt`.

### 5.1 Transport semantics

A transaction is `transaction(address7Bit, writeData, readLength)`:

- Register select: `writeData = [register]`, `readLength = 0`; must return zero bytes.
- Pure read: `writeData = []`, `readLength = N`; returns N bytes from the selected register.
- Register write: `writeData = [register, ...data]`, `readLength = 0`; must return zero bytes.

The app retries the complete select/read pair for up to 2,000 ms with 20 ms spacing on
`I2cTransportException`, because the coprocessor can NACK while asleep and a retry of only the
read half would read the old register.

### 5.2 Register map

| Register | R/W | Meaning |
| --- | --- | --- |
| `0x00` | R | Device version (discovery). `0x00` and `0xFF` are treated as no device. |
| `0x02` | R | Protocol major, raw byte (no policy imposed by the client). |
| `0x05` | R | Error code (best-effort diagnostic). |
| `0x10` | R/W | Auth control/status. Write `0x01` to start; poll until `0x10` = success. |
| `0x11` | R | Response length, u16 big-endian. |
| `0x12` | R | Response data. |
| `0x20` | W | Challenge length, u16 big-endian. |
| `0x21` | W | Challenge data. |
| `0x30` | R | Certificate length, u16 big-endian. |
| `0x31` | R | Certificate data window 0 (128 bytes). |
| `0x32` | R | Certificate data window 1 (128 bytes). |
| `0x33` … | R | Subsequent windows; each window is 128 bytes. |

### 5.3 Operations

Discovery (`MfiDeviceScanner`):

- Candidates, in order: `0x10`, then `0x11` (7-bit addresses).
- Select `0x00`, then pure-read 1 byte.
- Accept a device version other than `0x00`/`0xFF`.
- Retry the candidate cycle for up to 2,000 ms at 20 ms intervals; first valid response wins.

Certificate read:

1. Read u16 at `0x30`.
2. Require `1 <= length <= maximumOutputLength` (default 65,525).
3. For `offset = 0, 128, 256, …`, select `0x31 + offset/128`, read
   `min(128, length - offset)`, copy into the output.

Challenge signing:

1. Write u16 big-endian challenge length at `0x20`.
2. Write the challenge bytes at `0x21`.
3. Write `0x01` at `0x10` (start).
4. Sleep 10 ms; poll `0x10` every 10 ms until it reads `0x10`, or fail after 3,000 ms.
5. Read u16 at `0x11`; require `1..65,525`.
6. Read that many bytes at `0x12`.

If the poll times out, the client makes a best-effort read of `0x05` for an error code.

## 6. Local software signer (protocolMajor 3)

Source: `shared/src/main/java/com/shilapi/xcertplay/mfi/LocalMfiAuthenticationClient.kt`.

- Identity directory: `offline-mfi/` under `noBackupFilesDir`.
- `identity.pk8`: PKCS#8 EC private key; max 16 KiB.
- `certificate.p7b`: PKCS#7; `CertificateFactory.generateCertificates` must produce exactly
  one certificate; public key must be EC P-256 with order
  `ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`.
- Load-time self-test: sign a random 32-byte challenge and verify with the certificate public
  key; a mismatch fails closed.
- `protocolMajor()` returns `3`.
- `readCertificate(max)`: returns the loaded `certificate.p7b` bytes; requires
  `certificate.size <= max`.
- `signChallenge(challenge)`:
  - Requires exactly 32 bytes.
  - `Signature.getInstance("NONEwithECDSA")` over the 32-byte digest (no re-hash).
  - Converts the DER ECDSA signature to 64-byte raw `r || s` (`derToRaw`), rejecting
    non-positive or >256-bit integers and handling a 33-byte leading-zero integer.
- `certificateType` = `MFI`.

`LocalMfiProbe` exercises the same path twice with 3 fresh digests each and verifies that a
changed digest is rejected.

## 7. Remote MFi HTTP contract

Source: `shared/src/main/java/com/shilapi/xcertplay/mfi/RemoteMfiAuthenticationClient.kt`;
upstream API table in `DiPlay-main/docs/UPSTREAM-README.md` (Remote MFI section).

Base address must be `https://`, or `http://` only when the host is a private/loopback
literal or a trusted single-label/.local name. Redirects are disabled; caching is disabled.

### 7.1 `GET /mfi/certificate`

Success body (flat JSON object):

```json
{
  "protocolMajor": 3,
  "type": "mfi",                     // optional; "mfi" (default) or "baa"
  "certificate": "<base64>",         // MFI: certificate bytes; BAA: package
  "certificateSha256": "<64 hex>"    // SHA-256 of the decoded certificate bytes
}
```

- `protocolMajor` must be `0..255`.
- `certificate` must decode to `1..65,525` bytes.
- `certificateSha256` must be 64 hex characters and match the decoded bytes.
- For `type = "baa"`, `certificate` is `u32 leafLength | u32 intermediateLength | leaf || intermediate`;
  lengths must be positive, the total must match exactly, and the client builds the iAP2
  `0xAA01` payload (`param 0 = leaf`, `param 1 = 0x01`, `param 2 = intermediate`).
- The client caches the certificate info after the first successful call.

### 7.2 `POST /mfi/sign`

Request:

```json
{ "challenge": "<base64 1..128 bytes>", "requestId": "<uuid>" }
```

Success: `{ "signature": "<base64 1..65,525 bytes>" }`.

The client retries on `408`, `429`, and `5xx` (default 2 attempts total) with the **same**
`requestId`; it does not retry other `4xx`. Read timeout default 10,000 ms; connect timeout
default 5,000 ms.

### 7.3 `POST /mfi/reset`

Request: `{}`. Success: `{ "detail": "" }`.

`reset()` clears the client's cached certificate info and is never retried. A non-2xx response
surfaces `{ "detail": "..." }` as `RemoteMfiHttpException(statusCode, detail)`.

### 7.4 Common rules

- `Accept` and `Content-Type`: `application/json; charset=utf-8`.
- Optional `Authorization: Bearer <token>`.
- Response body limit: 2 MiB; exceeding it is an I/O failure.
- Non-2xx responses use `{ "detail": "..." }`; a missing/blank detail becomes `HTTP <status>`.
- Error classes: `MfiInvalidDataException`, `RemoteMfiException`,
  `RemoteMfiHttpException`, `MfiAuthenticationFailedException`, `Iap2MfiAuthenticationException`.

## 8. Failure and timeout summary

| Path | Failure | Behavior |
| --- | --- | --- |
| CSM | bad length / garbage | advance one byte and rescan; frames below 6 bytes are ignored until a valid header |
| iAP2 auth | unexpected message | throw and abort |
| iAP2 auth | challenge outside 1..128 | throw and abort |
| iAP2 auth | deadline exceeded | timeout failure |
| Coprocessor | NACK on select/read | retry pair up to 2 s |
| Coprocessor | auth poll timeout | read `0x05` best-effort, throw |
| Coprocessor | short read | `MfiInvalidDataException` |
| Local signer | challenge != 32 bytes | `IllegalArgumentException` |
| Local signer | key/cert mismatch | load fails closed |
| Remote | SHA mismatch | `MfiInvalidDataException` |
| Remote | unknown `type` | `MfiInvalidDataException` |
| Remote | retryable status | retry with same `requestId` |
| Remote | non-retryable status | throw immediately |
| SAP | wrong version/length | return `null` |
| SAP | zero shared secret | return `null` |

## 9. Source references

| Concern | File |
| --- | --- |
| Authenticator contract | `shared/src/main/java/com/shilapi/xcertplay/mfi/MfiAuthenticationClient.kt` |
| Local P-256 provider | `shared/src/main/java/com/shilapi/xcertplay/mfi/LocalMfiAuthenticationClient.kt` |
| Remote HTTP provider | `shared/src/main/java/com/shilapi/xcertplay/mfi/RemoteMfiAuthenticationClient.kt` |
| iAP2 auth loop | `shared/src/main/java/com/shilapi/xcertplay/mfi/Iap2MfiAuthenticationClient.kt` |
| iAP2 auth messages | `shared/src/main/java/com/shilapi/xcertplay/iap2/message/Iap2Messages.kt` |
| iAP2 endpoint catalog | `shared/src/main/java/com/shilapi/xcertplay/iap2/catalog/Iap2Endpoint.kt` |
| CSM framing | `shared/src/main/java/com/shilapi/xcertplay/iap2/wire/Iap2CsmFramer.kt` |
| Discovery / self-check | `shared/src/main/java/com/shilapi/xcertplay/mfi/MfiDeviceScanner.kt`, `MfiSelfCheck.kt` |
| AirPlay MFiSAP | `shared/src/main/java/com/shilapi/xcertplay/airplay/MfiSapAuthSetup.kt` |
| Runtime wiring | `shared/src/main/java/com/shilapi/xcertplay/orchestration/CarPlayController.kt` (lines 928-995) |
| Identity bootstrap | `common/src/main/java/com/shilapi/xcertplay/DiPlayBootstrap.kt` |
