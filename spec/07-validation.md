# Validation

Recorded on 2026-10-28 with Node.js v26.12.1 and OpenSSL 4.1.0 on macOS (darwin/arm64).

## 1. Automated checks

```sh
cd mfi-model
npm test
```

Result: **67 tests, 67 pass, 0 fail, 0 skipped** (the Apple-certificate negative check runs
because the APK is present). The suite has no network calls and installs no packages.

```sh
node src/cli.js selftest
```

Observed:

```
PASS ecdsa rawDigest=32 signature=64 protocolMajor=3
PASS csm frame=0x4040 header=6
PASS coprocessor windows=128 challenge=20 signature=128
PASS iap2 0xAA00-0xAA05 signature=64
PASS sap x25519=ok aes-ctr=ok signature=64
PASS remote url=http://127.0.0.1:<ephemeral> endpoints=3
PASS selftest pki=<workspace>/mfi-model/build/test-pki
```

```sh
node src/cli.js iap2-selftest
node src/cli.js sap-selftest
```

Observed:

```
PASS iap2 certificate=545 signature=64
PASS sap certificate=545 signature=64
```

## 2. Wire vectors

```sh
node src/cli.js vectors
```

Observed (matches `spec/03-wire-vectors.md`):

```
aa00  40400006aa00
aa01  4040000daa0100070000414243
aa02  4040002aaa0200240000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
aa03  4040004aaa0300440000808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
aa05  40400006aa05
```

## 3. Remote service

```sh
node src/cli.js serve --port 8799 &
node --input-type=module -e "
  const base='http://127.0.0.1:8799';
  console.log(await (await fetch(base+'/mfi/certificate')).json());
  console.log(await (await fetch(base+'/mfi/reset',{method:'POST',body:'{}'})).json());
  const r=await (await fetch(base+'/mfi/sign',{method:'POST',
    body:JSON.stringify({challenge:Buffer.alloc(32,7).toString('base64'),requestId:'r1'})})).json();
  console.log(Buffer.from(r.signature,'base64').length);
"
```

Observed: certificate JSON with `protocolMajor: 3`, a base64 certificate, and a matching
`certificateSha256`; reset returns `{"detail":""}`; the signature decodes to 64 bytes.
`--baa` returns `type: "baa"` and a `u32 leafLen | u32 intLen | leaf || intermediate` package
(observed 515-byte leaf, 475-byte intermediate, 998-byte package).

## 4. APK public profile

```sh
node src/cli.js analyze-apk
```

Observed:

```
subject=C=US, O=Apple Inc., OU=Apple Accessories, CN=IPA_24ACBB48646F8077F7463523085B60D2
issuer=C=US, O=Apple Inc., OU=Apple Certification Authority, CN=Apple Accessories Certification Authority - 00000002
notBefore=Jun 13 08:32:59 2018 GMT
notAfter=Dec 31 23:59:59 2049 GMT
Public-Key: (256 bit field, 128 bit security level)  NIST CURVE: P-256
Apple MFi marker 1.2.840.113635.100.6.36: present (critical)
key-cert-match: yes
```

The script writes only to a mode-700 `mktemp` directory and removes it on exit. It does not
print, copy, or persist the private key.

## 5. Manual DiPlay integration (operator-run)

This host has no JDK, Gradle, Kotlin, or Android SDK, so the app was not built or installed here.
The steps and expected observation are:

1. On a machine with JDK 17+ and the Android SDK, follow `DiPlay-main/docs/BUILD.md`.
2. Start the model on a private/loopback address:
   `node src/cli.js serve --host 0.0.0.0 --port 8787` (add `--token <secret>` if desired).
3. In DiPlay, select the `REMOTE` MFi target and set the server address to
   `http://<LAN-IP>:8787` (cleartext is accepted only on private/loopback hosts).
4. Expect `mfi remote service ready`, `protocolMajor=3`, and the iAP2 trace
   `rx=0xaa00`, `tx=0xaa01`, `rx=0xaa02`, `tx=0xaa03`.
5. Expect the iPhone to reject the synthetic certificate (`AuthenticationFailed` / session
   failure) because it is not Apple-issued. That is the designed boundary of this model, not a
   defect.

If a user-supplied authorized MFi identity is later added (a separate, explicitly scoped
change), the same iAP2/SAP/remote paths can carry it; this repository does not extract or use
the identity bundled in the APK.

## 6. REA decompilation of the shipped APK

```sh
export JAVA_HOME=<jdk-21>
export REA_JADX_MCP_JAR=<jadx-headless-mcp-0.7.1-all.jar>
npx -y rea-agents@6.8.0 doctor --provider jadx --json       # jadx: healthy
npx -y rea-agents@6.8.0 inspect-android-package DiPlay-0.2.22.apk --format json
tools/rea-decompile-apk.sh build/decompiled                  # per-method evidence
```

Observed: `jadx` 0.7.1, `Loaded classes: 30621, methods: 193307, instructions: 5629041`;
package `com.shihab.diplay` 0.2.22 (versionCode 41, minSdk 24, targetSdk 37). 147 selected
classes decompiled to Java; every constant in `spec/02-protocol.md` matched. Details and
evidence ids: `spec/05-rea-shipped-dex.md`.

## 7. libmfi (Linux module)

```sh
cd mfi-linux
make
make test        # PASS (0 failures)
make selftest
```

Observed on macOS/arm64 with OpenSSL 4.1.0 (the C code is POSIX + OpenSSL 3/4 and builds
unchanged on Linux):

```
ok   iAP2 signature verifies
ok   decrypted SAP signature verifies (protocol major 3 path)
ok   coprocessor serves the same certificate container (472 bytes)
ok   coprocessor signs a 32-byte digest
ok   accessory reports success
ok   accessory aborts on unknown message
PASS (0 failures)
```

```
authenticator: local-p256
protocol major: 3
certificate: 472 bytes (sha256 b3b8e94d…)
sign: 64 bytes r||s e38324fc…
csm: frame 42 bytes, message 0xaa02, 1 parameter
sap: reply 576 bytes, cert 472, signature 64 (verified)
coprocessor: discovery + certificate + sign OK
PASS
```

End to end over a PTY, with a phone-side simulator driving `mfid serve --pty --once`:

```
iap2 mfi rx=0xaa00 request-certificate
iap2 mfi tx=0xaa01 certificate bytes=555
iap2 mfi rx=0xaa02 challenge bytes=32
iap2 mfi tx=0xaa03 signature bytes=64
iap2 mfi rx=0xaa05 authentication-succeeded
authentication succeeded
```

Cross-implementation check (Node model frames + C accessory over a PTY):

```sh
node tools/crosscheck-mfid.mjs
```

```
ok   Node CSM decoder accepts the C frame
ok   certificate equals the loaded container
ok   signature verifies with the Node model (raw digest ECDSA)
ok   signature verifies with the C library (OpenSSL)
ok   mfid exited cleanly
PASS (0 failures)
```

The shipped 607-byte Apple container also loads in the module (`mfid cert`, temp directory,
key removed afterwards): subject `CN=IPA_24ACBB48646F8077F7463523085B60D2`, serial
`24ACBB48646F8077F7463523085B60D2`, leaf SHA-256 `58d50d668e5fb0a249dfcec0997019b8d28db3afcc3b6dad31ae1cf41e895a16`,
key/certificate match confirmed by the loader.

## 8. Evidence index

| Claim | Source |
| --- | --- |
| APK hash and inventory | `ev_315e53a4ae07fbef25c7aa09351de6049e3c3b161424c49e01f56a4340b48086` |
| APK v2 signer | `ev_b54b1a74123ddfba7a4b0dc496115bb431bcb986ff55bd5c3d3560452a012ad8` |
| Certificate profile | `tools/analyze-apk-identity.sh` output; `spec/01` |
| MFi class/string presence | `unzip -p … classes3.dex \| strings -a \| grep …`; `spec/01` |
| Native transport only | `nm -D` plus `inspect_native_exports` (`ev_5e9580caa1dd40d1629d4202a0aa604ab3dc35862cfc3e6d833b5a1854fed0e7`); `spec/01` |
| Protocol semantics | `spec/02`; shipped-DEX confirmation and evidence ids in `spec/05-rea-shipped-dex.md` |
| Decompiled MFi classes | `inspect_android_package` `ev_423c07ae…`, class and method records listed in `spec/05-rea-shipped-dex.md` |
| libmfi behaviour | `mfi-linux/test/test_main.c`, `make test`, `mfid selftest` |
| Wire vectors | `spec/03`; `node src/cli.js vectors` |
| Open questions | `spec/04` |

## 9. Residual limitations

- Android decompilation needs a caller-supplied JDK and `jadx-headless-mcp`; it is not part of
  REA setup and must be provided per host.
- No real iPhone / accessory hardware was used; no real MFi acceptance is claimed.
- `libmfi`'s I2C backend was exercised against the software coprocessor only; the physical bus
  path (`ioctl I2C_RDWR`) is compiled but not bench-tested here.
- BAA signing over a 64-byte input is modelled, not established.
- The model's remote server is an HTTP test service; production transport/security policy
  (TLS, token provisioning, deployment) is out of scope.
