# Wire vectors

Reproducible byte/JSON vectors for the model and its tests. All multi-byte integers are
big-endian. `…` denotes a repeated byte range; the model tests generate those bytes.

## 1. iAP2 CSM

### 1.1 Empty request

`0xAA00` `RequestAuthenticationCertificate`, no parameters:

```
40 40 00 06 AA 00
```

### 1.2 Certificate `41 42 43`

`0xAA01` with one parameter: id 0, payload 3 bytes. Parameter length = 4 + 3 = 7;
body = 7; frame length = 6 + 7 = 13.

```
40 40 00 0D AA 01 00 07 00 00 41 42 43
```

### 1.3 32-byte challenge `00 01 … 1F`

`0xAA02`; parameter length = 4 + 32 = 36 (`0x24`); body 36; frame length 42 (`0x2A`):

```
40 40 00 2A AA 02 00 24 00 00
00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
```

### 1.4 64-byte signature `80 81 … BF`

`0xAA03`; parameter length = 4 + 64 = 68 (`0x44`); body 68; frame length 74 (`0x4A`):

```
40 40 00 4A AA 03 00 44 00 00
80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F
90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F
A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF
B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF
```

### 1.5 Success

`0xAA05`:

```
40 40 00 06 AA 05
```

### 1.6 BAA `0xAA01` with leaf `AA BB`, intermediate `CC DD`

Raw body (not `Iap2ParameterList`-normalized by `Iap2Messages.build`; it is built by
`baaCertificatePackage`):

```
param 0: 00 06 00 00 AA BB
param 1: 00 05 00 01 01
param 2: 00 06 00 02 CC DD

frame: 40 40 00 17 AA 01
       00 06 00 00 AA BB
       00 05 00 01 01
       00 06 00 02 CC DD
```

### 1.7 Parser tolerance

Input chunks may include garbage before `40 40`; the framer discards bytes one at a time until
a header with `length >= 6` is found. Concatenated frames are returned in order.

## 2. AirPlay MFiSAP

### 2.1 Request

Version 1 and a 32-byte peer X25519 public key (shown as `11` repeated):

```
01 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
   11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
```

Length must be exactly 33. Version must be `0x01`; otherwise the handler returns `null`.

### 2.2 Response layout (MFI)

```
offset  size  field
0       32    accessory ephemeral X25519 public key
32      4     certificate length (u32)
36      N     certificate bytes (as returned by readCertificate)
36+N    4     encrypted signature length (u32)
40+N    M     AES-128-CTR(signature)
```

For BAA, after the encrypted signature:

```
+0      4     baicBlob length (u32)
+4      K     OPACK baIC intermediate blob
```

### 2.3 Key schedule

```
shared  = X25519(accessoryPrivate, peerPublic)      # 32 bytes, reject if all zero
aesKey  = SHA-1("AES-KEY" || shared)[0..15]
aesIv   = SHA-1("AES-IV"  || shared)[0..15]
digest  = protocolMajor == 2
          ? SHA-1(accPublic || peerPublic)
          : SHA-256(accPublic || peerPublic)
sig     = signChallenge(digest)                     # 64-byte raw r||s for P-256
enc     = AES-128-CTR(aesKey, aesIv, sig)
```

### 2.4 `baIC` OPACK header

| Intermediate length | Bytes |
| --- | --- |
| 0x00..0x20 | `E1 44 62 61 49 43 (0x70 + len)` |
| 0x21..0xFF | `E1 44 62 61 49 43 91 len` |
| 0x100..0xFFFF | `E1 44 62 61 49 43 92 lenLo lenHi` |
| > 0xFFFF | `E1 44 62 61 49 43 93 len0 len1 len2 len3` |

`44` is the OPACK marker for the key `"baIC"`; `62 61 49 43` is ASCII `baIC`.

## 3. Coprocessor register sequences

### 3.1 300-byte certificate

```
select 0x30            write [30]              read 0
pure read              write []                read 2      -> 01 2C
select 0x31            write [31]              read 0
pure read              write []                read 128    -> cert[0..127]
select 0x32            write [32]              read 0
pure read              write []                read 128    -> cert[128..255]
select 0x33            write [33]              read 0
pure read              write []                read 44     -> cert[256..299]
```

### 3.2 20-byte challenge, 128-byte signature

```
write 0x20  [20 00 14]
write 0x21  [21 <20 challenge bytes>]
write 0x10  [10 01]
select 0x10 [10]
pure read   []  read 1   -> 10
select 0x11 [11]
pure read   []  read 2   -> 00 80
select 0x12 [12]
pure read   []  read 128 -> <signature>
```

### 3.3 Discovery

```
select 0x00 [00]   read 0
pure read   []     read 1
```

For candidate `0x10`, a response of `FF` (floating bus) is invalid; the scanner then tries
`0x11`. A valid device version is any byte except `00` and `FF`.

## 4. Remote HTTP

### 4.1 Certificate response (MFI)

```json
{
  "protocolMajor": 3,
  "type": "mfi",
  "certificate": "<base64 of the certificate bytes>",
  "certificateSha256": "<64 lowercase hex characters>"
}
```

`type` may be omitted; the client defaults to `"mfi"`. For `"baa"`, `certificate` is:

```
u32 leafLength | u32 intermediateLength | leaf || intermediate
```

### 4.2 Sign request/response

Request:

```json
{ "challenge": "AQIDBA==", "requestId": "5f0c2f0e-..." }
```

Response:

```json
{ "signature": "<base64 of 64 bytes for P-256>", "requestId": "5f0c2f0e-..." }
```

The model server returns `requestId` as a convenience; the DiPlay client ignores extra fields.
On a retry with the same `requestId` and the same challenge, the server returns the same
signature.

### 4.3 Reset

Request `{}`; response `{ "detail": "" }`.

### 4.4 Error

Non-2xx response:

```json
{ "detail": "chip reset failed" }
```

## 5. ASN.1 markers

Apple MFi marker OID `1.2.840.113635.100.6.36`:

```
06 09 2a 86 48 86 f7 63 64 06 24
```

Model test OID `1.3.6.1.4.1.55555.1`:

```
06 09 2b 06 01 04 01 83 b2 03 01
```

The model's negative test asserts that a synthetic certificate does **not** contain the Apple
marker and that its issuer is the generated test CA, not an Apple CA.
