# libmfi in LIVI: the `mfid` port as an upstream feature

This note records what was added to LIVI upstream, why, exactly what the code does, what was
verified on this machine, and what is still waiting on a human. The short version: the software
MFi built here (`identity.pk8` + `certificate.p7b`, the same contract `libmfi` implements) is now
something LIVI *serves* on its MFi port, not only something its helper reads locally.

- Pull request: [f-io/LIVI#398](https://github.com/f-io/LIVI/pull/398) — `feat(mfid): serve the imported identity on the MFi port`
- Issue (opened first, as `CONTRIBUTING.md` requires): [f-io/LIVI#397](https://github.com/f-io/LIVI/issues/397)
- Branch: `feat/mfid-imported-files` in the fork [`AltusRossouw/LIVI`](https://github.com/AltusRossouw/LIVI)
- Base: `f-io/LIVI@c06d3eb` (`main`, 2026-10-28), 2 commits, 4 files, +223/−19
- Local clone used for the work: `~/Documents/GitHub/LIVI` (a separate clone; `~/tools/LIVI` was left untouched)

## 1. What LIVI had, and the gap this closes

[LIVI](https://github.com/f-io/LIVI) implements the CarPlay accessory side and needs MFi
authentication, exactly like DiPlay does. Upstream has three MFi sources:

| Source | Where | Sees the identity |
| --- | --- | --- |
| I²C coprocessor | `iap2-mfi/src/linux.rs` (`I2cCoprocessor`) | inside the chip |
| LIVI Link over TCP | `iap2-mfi/src/ncm.rs` (`NcmCoprocessor`) | inside the dongle |
| Imported files | `iap2-mfi/src/file.rs` (`FileCoprocessor`) | `certificate.p7b` + `identity.pk8` |

`livi-helperd` already preferred the imported files on both platforms (`mfi_files::open()` is tried
before the chip), so file-backed MFi itself is not new — that was issue
[f-io/LIVI#375](https://github.com/f-io/LIVI/issues/375), closed with nightly #2517.

What was still missing is the *serving* side. `livi-mfid` — the daemon that offers MFi on port 5000,
the endpoint a LIVI Link provides for a head unit — opened an I²C chip and nothing else:

```rust
// native/crates/livid/src/mfid.rs, before
let mut chip = match I2cCoprocessor::open(bus, -1) {
    Ok(chip) => chip,
    Err(e) => {
        eprintln!("[mfid] no MFi chip on i2c-{bus}: {e}");
        let _ = fs::remove_file(STATE);
        return 1;
    }
};
```

So two real setups had no MFi endpoint at all:

- a board with the identity staged in `~/.config/LIVI/mfi` and no coprocessor, and
- any Mac, which has no I²C bus to put a chip on.

That is the gap `mfid net` in `libmfi` has always covered (`mfi-linux/src/mfid_server.c`,
`mfid --identity DIR net`), and it was already cross-checked against LIVI's own `NcmCoprocessor`
in [spec/06 §3.1](06-livi-integration.md). This change brings that capability into LIVI itself, in
Rust, behind the same precedence the helper uses.

## 2. What the two commits contain

### 2.1 `585fdca` — `feat(iap2-mfi): check an imported identity signs for its own key`

`FileCoprocessor` gained `self_test()`: it signs a fixed digest with the loaded key and verifies the
result against the public half, so an unusable identity is caught where it can be reported instead of
mid-session.

```rust
pub fn self_test(&mut self) -> Result<(), MfiError> {
    let digest = match &self.identity {
        Identity::Ec(_) => vec![0x5A; 32],
        Identity::Rsa(_) => vec![0x5A; SHA1_LEN],
    };
    let signature = self.generate_challenge_response(&digest)?;
    match &self.identity {
        Identity::Ec(key) => { /* verify_prehash, raw r||s */ }
        Identity::Rsa(key) => { /* PKCS#1 v1.5 over a SHA-1 digest */ }
    }
}
```

This mirrors the `libmfi` loader contract (`mfi_identity_load_dir`, `mfi-linux/src/identity.c`): a
key that cannot sign, or that signs in a form the verifier rejects, is a broken identity, not a
session bug. One new test covers both key types (`the_self_test_signs_and_verifies_for_both_key_types`).

### 2.2 `5af1898` — `feat(mfid): serve the imported identity on the MFi port`

`livid/src/mfid.rs` now picks between the two sources the helper knows, and reports which one it
serves. Argument handling:

| Invocation | Serves |
| --- | --- |
| `livi-mfid` | the imported files when either file is present, else the chip on `i2c-1` (the old default) |
| `livi-mfid 2` | the chip on `i2c-2` — unchanged, so the dongle `rcS` (`livi-mfid $MFI_I2C`) behaves exactly as before |
| `livi-mfid --files` | the imported files from `~/.config/LIVI/mfi` |
| `livi-mfid --files /etc/mfi` | the imported files from an explicit directory |

The default directory is the one `livi-helperd` uses (`~/.config/LIVI/mfi`, derived from
`SUDO_USER`/`USER`/`HOME`), so an identity staged for the helper is also the identity the port serves.

Serving a files back-end means touching one more thing in the crate manifest, because `livid` did not
compile `FileCoprocessor` at all:

```toml
iap2-mfi = { workspace = true, features = ["files"] }
```

Two smaller decisions:

- **`self_test` before offering.** A broken identity is refused at startup with a printed reason
  (`[mfid] MFi files in … do not sign: …`) and the state file is cleared, instead of the phone
  discovering it. If the files are bad *and* a chip exists, `--files`/`<bus>` pins the source
  explicitly, so nothing silently switches underneath an operator.
- **The state file names the source.** `/tmp/livi/mfi` is what the web page shows as the coprocessor
  (`livi-web/src/lib.rs`, `status_json` → `cp`), so the format stays one line and gains the label:

  ```
  Gen3 @ files:/root/.config/LIVI/mfi      # before: Gen3 @ /dev/i2c-1
  Gen3 @ /dev/i2c-1
  ```

`README.md` documents the third route and both daemon sources in the "MFi Authentication" section.

## 3. Design choices, and what was deliberately left out

| Decision | Why |
| --- | --- |
| Rust port inside `iap2-mfi`, not the C library | LIVI is a Cargo workspace with a pinned toolchain and `-D warnings`; a second build system, OpenSSL linkage and a C ABI would not be reviewable as one feature. The wire contract is what matters, and the cross-checks in spec/06 already pin it. |
| Files first, chip second | Exactly the order `livi-helperd` already uses; two components disagreeing about precedence would be a bug waiting for a support ticket. |
| Positional bus stays the chip | `scripts/livi-link/common/rootfs/etc/init.d/rcS` starts `livi-mfid $MFI_I2C` on a dongle; a bare number must keep meaning "that chip". |
| No certificate parsing | Key↔certificate *matching* needs an X.509/PKCS#7 reader: `libmfi` gets it from OpenSSL (`X509_check_private_key`, `identity.c:133`), LIVI has no such dependency. `self_test` proves the key is usable and self-consistent, which is what a bad `/auth-setup` usually is; a cert/key mismatch still surfaces as a failed session. This is the honest limit of the check. |
| No MFiSAP v1 / `/auth-setup` here | `libmfi` implements `mfi_sap_handle()` for AirPlay screen-mirroring accessories. LIVI negotiates MFi4 (`livi-cp/src/mfi4`); the v1 path does not belong in this change. |
| No generic byte-stream serve | `libmfi`'s `mfid serve --serial /dev/ttyGS0` and the I²C register simulator are transport work LIVI does not need: its wires are usbmuxd, NCM and the helper's own link. |

## 4. Verification

### 4.1 What ran on this machine

`iap2-mfi` is platform-neutral, so its tests run here directly:

```
$ cd ~/Documents/GitHub/LIVI/native
$ cargo test -p iap2-mfi --features files --locked
running 8 tests
… test file::tests::the_self_test_signs_and_verifies_for_both_key_types ... ok
test result: ok. 8 passed; 0 failed          # 7 before this change
```

Formatting and lint, for the two crates this touches:

```
cargo fmt --all --check                                        # clean
cargo clippy -p iap2-mfi --features files --all-targets --locked -- -D warnings
cargo clippy -p livid --target armv7-unknown-linux-musleabihf --all-targets --locked -- -D warnings
```

Both clippy runs are clean **except** one warning that is not from this change:
`clippy::large_enum_variant` on `iap2_mfi::file::Identity` (`Ec` 104 bytes vs `Rsa` 344 bytes, delta
> 200). It fires on this host for the macOS and `x86_64-unknown-linux-gnu` targets, and it fires on
**pristine upstream** too when rebuilt from scratch — the Linux runner that CI uses reports no such
warning (`checks` is green on `main@c06d3eb`), so it is a layout artifact of this machine, not a
regression, and it was left alone rather than smuggled into a feature PR. Verified by rebuilding
upstream `file.rs` from a stash and comparing.

The toolchain is the workspace's own pin: `beta-2026-10-18` → `rustc 1.100.0-beta.7 (fd8e211ae)`.

### 4.2 The new unit tests, executed for real

`livid` only builds for Linux, so its tests cannot run on this Mac. The argument-parsing functions
(`parse`, `bus`, `has_identity`) were therefore extracted verbatim into a throwaway crate and run
natively:

```
$ RUSTUP_TOOLCHAIN=stable cargo test        # /tmp/mfidparse, the four parse tests
test tests::an_imported_identity_wins_over_the_default_bus ... ok
test tests::a_bus_argument_still_pins_the_chip ... ok
test tests::the_files_can_be_named ... ok
test tests::a_bus_that_is_not_a_number_is_refused ... ok
test result: ok. 4 passed; 0 failed
```

### 4.3 The serve path, end to end

The interesting code path is "files in, mfid out". That is testable on this Mac without `livid`,
because it is all in `iap2-mfi`: open the identity, serve it with `server::listen`, and fetch it back
with the client LIVI itself uses (`NcmCoprocessor`). The identity was the one recovered in
[spec/01](01-artifact-and-identity.md) from `DiPlay-0.2.22.apk: assets/offline-mfi/`
(`CN=IPA_24ACBB48646F8077F7463523085B60D2`, 607-byte PKCS#7, P-256 key):

```
served certificate 607 bytes, signature verifies
test serving_the_imported_files_answers_the_client_livi_uses ... ok
```

What that run asserts, in order: `FileCoprocessor::open` + `self_test` pass; the listener accepts a
loopback peer; `NcmCoprocessor` reads protocol major **3**; `OP_GET_CERT` returns the container
**byte for byte**; `OP_SIGN` over a 32-byte digest returns **64 bytes of raw `r||s`** that verifies
against the key. The scratch test was deleted again — it pinned an absolute path and does not belong
in the tree.

### 4.4 What could not be run here

- `cargo clippy --workspace` / `cargo test --workspace` on Linux (the CI job). Only the two touched
  crates were linted, in both target layouts, plus `cargo fmt --all --check` over the whole workspace.
- Executing `livid` itself: no Linux host and no armv7 musl runtime on this Mac. The crate does
  `cargo check`/`clippy --all-targets` for `armv7-unknown-linux-musleabihf`, which is the target CI
  uses for the dongle daemon.
- A phone session against the new daemon, for the same reason.

## 5. Reproduce

```sh
# 1. the fork and a clean clone (never disturb ~/tools/LIVI, which has local edits)
gh repo fork f-io/LIVI --clone=false
git clone https://github.com/AltusRossouw/LIVI.git ~/Documents/GitHub/LIVI
cd ~/Documents/GitHub/LIVI && git remote add upstream https://github.com/f-io/LIVI.git

# 2. the workspace pins its toolchain; rustup fetches it on first use
rustup toolchain install beta-2026-10-18 --profile minimal --component clippy,rustfmt
git config core.hooksPath .githooks        # spdx headers + rustfmt on staged files

# 3. the workspace patches femtovg to native/vendor/femtovg (tracked in the repo)

# 4. checks, exactly as CI runs them where the host allows it
cd native
cargo fmt --all --check
cargo clippy -p iap2-mfi --features files --all-targets --locked -- -D warnings
cargo clippy -p livid --target armv7-unknown-linux-musleabihf --all-targets --locked -- -D warnings
cargo test -p iap2-mfi --features files --locked
```

Running the daemon on a Linux host with an identity staged:

```sh
mkdir -p ~/.config/LIVI/mfi && chmod 700 ~/.config/LIVI/mfi
cp identity.pk8 certificate.p7b ~/.config/LIVI/mfi/ && chmod 600 ~/.config/LIVI/mfi/*

livi-mfid                     # -> "[mfid] MFi from the imported files in /home/USER/.config/LIVI/mfi"
                              #    "[mfid] serving files:/home/USER/.config/LIVI/mfi, protocol major 3"
                              #    "[mfid] listening on :5000"
livi-mfid --files /etc/mfi    # pin an explicit directory
livi-mfid 1                   # pin the chip on i2c-1, the pre-change behaviour

# any mfid client can now read the certificate and request a signature
# (build the verifier first: cd mfi-linux && make)
python3 tools/livi-mfid-client.py 127.0.0.1 5000 --verify-bin mfi-linux/build/mfid \
        --identity /etc/mfi
```

## 6. State of the pull request

| Item | State |
| --- | --- |
| PR | [f-io/LIVI#398](https://github.com/f-io/LIVI/pull/398), open, `mergeable=MERGEABLE` |
| Issue | [f-io/LIVI#397](https://github.com/f-io/LIVI/issues/397) |
| Commits | `585fdca`, `5af1898`, both with an `Assisted-by: DeepSeek Harness` trailer, as `CONTRIBUTING.md` asks for disclosure |
| Author e-mail | `altusrossouw2@gmail.com` (the account address, which the CLA check needs) |
| `CLA` check | **fail** — "Not signed: AltusRossouw". Only the copyright holder can accept it, so it stays red until this comment is posted on the PR:<br>`I have read the CLA Document and I hereby sign the CLA` |
| `checks` workflow | `action_required` — GitHub holds workflows for a first-time fork contribution until a maintainer approves the run. Nothing has executed yet, so the Linux clippy/test job and the dprint lint job are still outstanding. |

## 7. Open ends

- **Follow-ups worth proposing separately**, one topic each: key↔certificate matching in the file
  loader (needs a PKCS#7/X.509 reader), and a `livi-mfid` mode that also emits the coprocessor
  register dialogue for non-TCP consumers.
- **Upstream might prefer different naming**: `--files` mirrors `mfi_files.rs` and the crate's
  `files` feature; if the maintainer wants a config key (`carPlayMfiFiles`) instead, the parse
  function is the only place to touch.
- **The identity stays out of the repository** — the PR contains no key material, only the code path
  that reads it.

## 8. Evidence index

| Claim | Source |
| --- | --- |
| The gap: `livi-mfid` opened only an I²C chip | `livid/src/mfid.rs@c06d3eb`; `scripts/livi-link/common/rootfs/etc/init.d/rcS:41` |
| The helper's precedence is files-then-chip | `livi-helperd/src/linux_main.rs` (`crate::mfi_files::open()` first) |
| File-backed MFi is upstream since #375 | [f-io/LIVI#375](https://github.com/f-io/LIVI/issues/375), nightly #2517 |
| mfid wire protocol and cross-checks | [spec/06 §2–3](06-livi-integration.md); `mfi-linux/src/mfid_server.c` |
| Identity used for the serve-path run | [spec/01](01-artifact-and-identity.md) (`CN=IPA_24ACBB48646F8077F7463523085B60D2`) |
| 8 crate tests, 4 parse tests, clippy/fmt results | §4 of this note; re-runnable via §5 |
| Upstream CI green on the base commit | `checks` run 40762499953 on `c06d3eb` |

## Appendix A. Where the change lives

| File | Lines | Commit | Blob |
| --- | --- | --- | --- |
| `native/crates/iap2-mfi/src/file.rs` | +42/−3 | `585fdca` | [file.rs](https://github.com/AltusRossouw/LIVI/blob/feat/mfid-imported-files/native/crates/iap2-mfi/src/file.rs) |
| `native/crates/livid/src/mfid.rs` | +165/−12 | `5af1898` | [mfid.rs](https://github.com/AltusRossouw/LIVI/blob/feat/mfid-imported-files/native/crates/livid/src/mfid.rs) |
| `native/crates/livid/Cargo.toml` | +1/−1 | `5af1898` | [Cargo.toml](https://github.com/AltusRossouw/LIVI/blob/feat/mfid-imported-files/native/crates/livid/Cargo.toml) |
| `README.md` | +15/−3 | `5af1898` | [README.md](https://github.com/AltusRossouw/LIVI/blob/feat/mfid-imported-files/README.md) |

The source-selection function, as shipped — the whole behaviour table of §2.2 lives here:

```rust
/// With no argument an imported identity wins, the same order the helper uses,
/// and a bus argument pins the chip.
fn parse(args: &[String], dir: &Path, imported: bool) -> Result<Source, String> {
    match args {
        [] if imported => Ok(Source::Files(dir.to_path_buf())),
        [] => Ok(Source::I2c(DEFAULT_BUS)),
        [flag] if flag == "--files" => Ok(Source::Files(dir.to_path_buf())),
        [flag, path] if flag == "--files" => Ok(Source::Files(PathBuf::from(path))),
        [arg] => bus(arg).map(Source::I2c),
        _ => Err(usage()),
    }
}
```
