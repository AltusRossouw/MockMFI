# Artifact and identity profile

Scope: the shipped `DiPlay-0.2.22.apk` and the `DiPlay-main/` source snapshot in this
workspace. This document records only public, reproducible observations. It never prints,
copies, or persists private-key material.

## 1. Artifact identity

| Field | Value |
| --- | --- |
| File | `DiPlay-0.2.22.apk` |
| Bytes | 19,042,758 |
| SHA-256 | `7d04db263834f22010a86847766928113d3503a273e4d2d3440d21552e173139` |
| Format | APK (ZIP container) |
| Signing | APK Signature Scheme v2, one signer, self-consistent |
| v2 signer cert SHA-256 | `87b38b12788dcb202a961215f2572e30ec2dc9d8ef4bc070d05f77e49291a363` |
| Container entries | 360 files, 304 graph nodes, 0 integrity contradictions |

Evidence:

- `ev_315e53a4ae07fbef25c7aa09351de6049e3c3b161424c49e01f56a4340b48086`
  (`inspect_artifact` summary; parent `ev_d8c4f343e87907df2d5d0f84386749d9c04d7c0456360b2751c8806f56eac320`).
- `ev_b54b1a74123ddfba7a4b0dc496115bb431bcb986ff55bd5c3d3560452a012ad8`
  (`inspect_apk_signature` summary; parent `ev_15eb8f184a6a3c514fcfcd1b72ad8ff0f12d0e5ab5ed7ead1a61e327e05f3254`).

Limitations carried from the evidence: signatures are structurally parsed, not
cryptographically verified; `self_consistent` means the declared content digest matches the
current bytes, not that a trusted producer signed them.

## 2. MFi runtime assets

Both files are read from `assets/offline-mfi/` and copied by `DiPlayBootstrap` into
`noBackupFilesDir/offline-mfi/` before `LocalMfiAuthenticationClient.load()`:

| Asset | Bytes | Format | Purpose |
| --- | ---: | --- | --- |
| `assets/offline-mfi/identity.pk8` | 67 | PKCS#8, EC P-256, unencrypted | Accessory signing key |
| `assets/offline-mfi/certificate.p7b` | 607 | PKCS#7 SignedData containing one X.509 leaf | Accessory MFi certificate presented to the phone |

The bootstrap source is `DiPlay-main/common/src/main/java/com/shilapi/xcertplay/DiPlayBootstrap.kt`
(lines 17-40); the loader is `DiPlay-main/shared/src/main/java/com/shilapi/xcertplay/mfi/LocalMfiAuthenticationClient.kt`
(lines 48-76).

## 3. Certificate profile (public fields)

Decoded with:

```sh
unzip -p DiPlay-0.2.22.apk assets/offline-mfi/certificate.p7b \
  | openssl pkcs7 -inform DER -print_certs -text -noout
```

| Field | Value |
| --- | --- |
| Version | X.509 v3 |
| Serial | `24:ac:bb:48:64:6f:80:77:f7:46:35:23:08:5b:60:d2` |
| Signature algorithm | `ecdsa-with-SHA256` |
| Issuer | `C=US, O=Apple Inc., OU=Apple Certification Authority, CN=Apple Accessories Certification Authority - 00000002` |
| Subject | `C=US, O=Apple Inc., OU=Apple Accessories, CN=IPA_24ACBB48646F8077F7463523085B60D2` |
| Not before | `Jun 13 08:32:59 2018 GMT` |
| Not after | `Dec 31 23:59:59 2049 GMT` |
| Public key | EC P-256 (`prime256v1`), 256-bit field |
| Critical extension | `1.2.840.113635.100.6.36` (Apple MFi marker OID) |
| Chain in the asset | 1 certificate (leaf only; no intermediate or root) |

The Apple marker OID DER encoding is:

```
06 09 2a 86 48 86 f7 63 64 06 24
```

## 4. Key/certificate consistency

`tools/analyze-apk-identity.sh` derives only the public half of `identity.pk8` and compares
its SubjectPublicKeyInfo DER with the certificate's. Observed result for this APK:

```
key-cert-match: yes
```

The comparison is reproducible from a clean extraction; the private key is written only to a
`mktemp` directory with mode 600 and removed by the script's `EXIT` trap. The script never
prints the private key, and this dossier does not record it.

## 5. Provenance and published caveats

`DiPlay-main/README.md` (line 25) states:

> This is **not an Apple-certified product**. The APK bundles an experimental accessory
> identity recovered from public Carlinkit firmware, not a newly provisioned MFi identity for
> DiPlay. A bundled private key is extractable.

`DiPlay-main/docs/SAFETY-REVIEW-2026-10-03.md` treats credential packaging in contributor
workflows as a P1 concern and records that public-tree checks reject credential containers in
source builds. The release APK intentionally contains the identity (README lines 63-68).

## 6. Code location in the APK

- MFi classes and strings are present in `classes3.dex`, confirmed by:

  ```sh
  unzip -p DiPlay-0.2.22.apk classes3.dex | strings -a | grep -E \
    'Local MFi v3|Expected a P-256|offline-mfi|identity\.pk8|certificate\.p7b|/mfi/|AES-KEY|AES-IV|RequestAuthenticationCertificate'
  ```

  Observed: `Local MFi v3 expects a 32-byte digest`, `Expected a P-256 accessory certificate`,
  `offline-mfi`, `identity.pk8`, `certificate.p7b`, `/mfi/certificate`, `/mfi/sign`,
  `/mfi/reset`, `AES-KEY`, `AES-IV`, `RequestAuthenticationCertificate`.

- A descriptor scan of the same DEX lists the shipped MFi classes:
  `MfiAuthenticator`, `MfiAuthenticationClient`, `LocalMfiAuthenticationClient`,
  `RemoteMfiAuthenticationClient`, `Iap2MfiAuthenticationClient`, `MfiDeviceScanner`,
  `MfiSelfCheck`, `MfiCertificateType`, `BaaCertificatePair`, `RemoteMfiJson`, and
  `airplay/MfiSapAuthSetup` (plus their Kotlin synthetic/companion classes). This confirms the
  compiled APK contains the same MFi layer described by the source snapshot.

- Native `lib/<abi>/libxcertplay_i2c.so` exports only:

  ```
  Java_com_shilapi_xcertplay_transport_LinuxI2cNative_open
  Java_com_shilapi_xcertplay_transport_LinuxI2cNative_transaction
  Java_com_shilapi_xcertplay_transport_LinuxI2cNative_close
  ```

  with libc dependencies (`open`, `ioctl`, `close`, `malloc`, `free`, `strerror`). There is no
  MFi cryptography in native code; the native library is the Linux `/dev/i2c-N` transport.
  REA `inspect_native_exports` on the arm64-v8a file (SHA-256
  `25990da39b68c135edfb0781dacce2617bca2740851b44ed773507ca1cd6c420`, 6,760 bytes) reports
  exactly 3 exports and 0 issues; evidence
  `ev_5e9580caa1dd40d1629d4202a0aa604ab3dc35862cfc3e6d833b5a1854fed0e7`
  (parent `ev_c9d4497a63a2cc2bdffae005b27200dea0d9bccda7ff6a217442ef26a4b3a229`).

## 7. Method and limitations

- The APK was decompiled with REA's Android (JADX) provider after supplying a caller-provided
  JDK 21 and `jadx-headless-mcp` 0.7.1 (`REA_JADX_MCP_JAR`). `spec/05-rea-shipped-dex.md`
  records the tooling, the evidence ids, the decompiled corpus (147 classes) and the
  line-by-line confirmation of every protocol constant.
- The published source snapshot and the shipped `classes3.dex` agree on the authentication
  layer; the decompiled shipped code is treated as authoritative.
- Signature verification is structural only (`inspect_apk_signature`), as recorded in §1.
- If APK-level decompilation is required later, supply a jadx-headless-mcp 0.7.1 JAR and set
  `REA_JADX_MCP_JAR`, then inspect `com.shilapi.xcertplay.mfi.*` with the REA Android tools.
