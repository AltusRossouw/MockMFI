# HUDIY: where MFi actually happens

[HUDIY](https://hudiy.eu) (Wiboma Sp. z o.o.) is a commercial head-unit platform for Linux —
Raspberry Pi Zero 2 / 3 / 4 / 5 and x86_64, Debian Trixie or Raspberry Pi OS. Its core is
proprietary (one-time licence, installer only), while configuration schemas, examples and the
API proto are published at [github.com/wiboma/hudiy](https://github.com/wiboma/hudiy).

This note records what HUDIY does for CarPlay and what that means for `libmfi`: there is no MFi
integration point to wire, and the tooling below exists so a HUDIY user can still see which
identity is authenticating their phone.

## 1. CarPlay in HUDIY is a dongle feature

From the published documentation (`README.md`, "CarPlay projection"):

> CarPlay projection is served via a CarlinKit CPC200-CCPA or CPC200-Autokit dongle. Both models
> support USB and Wi-Fi connections.
>
> Hudiy can retrieve media metadata and navigation information from CarlinKit CPC200-CCPA/CPC200-Autokit
> and exposes this data through the API.

The published configuration confirms it — `config/main_configuration.json` carries an `autobox`
block and nothing else CarPlay-specific:

```json
"autobox": {
  "oemName": "Hudiy",
  "autoWirelessConnection": true,
  "allowedDevices": [
    { "vendorId": 4884, "productId": 5408 },
    { "vendorId": 4884, "productId": 5409 }
  ],
  "bandwidth": "AUTO",
  "fps": "30",
  "enumerateUsb": true
}
```

`4884` is `0x1314`, and `5408`/`5409` are `0x1520`/`0x1521` — the dongle's USB IDs. HUDIY's job is
to drive that dongle, decode the video stream and expose media/navigation data; the iPhone never
speaks iAP2 to HUDIY itself.

## 2. Therefore the MFi identity lives in the dongle

Nothing in HUDIY's documentation, configuration schema (`main_configuration.json`,
`applications.json`, …) or API proto configures a certificate, key, coprocessor bus or MFi mode.
The accessory identity is inside the CarlinKit firmware: the same family of firmware that DiPlay's
own README says its identity was "recovered from Carlinkit firmware", and whose certificate this
repository profiles in `spec/01`.

So for HUDIY + CarPlay:

```
iPhone ──USB/Wi-Fi──> CarlinKit CPC200 (MFi accessory) ──USB/Wi-Fi──> HUDIY (UI, video, API)
                              ▲
                              └── holds the MFi identity, answers AccAuthentication and /auth-setup
```

`libmfi` is not in that path and cannot be substituted for the dongle: HUDIY speaks the dongle's
private protocol, not iAP2, and it has no AirPlay/CarPlay session stack of its own.

## 3. What this repository adds for HUDIY users

| Tool | Purpose |
| --- | --- |
| `tools/dongle-mfi-profile.py` | Profile the MFi identity inside a dongle image, firmware dump, tar/zip archive or extracted directory: subject, issuer, serial, validity, SHA-256, the Apple MFi marker `1.2.840.113635.100.6.36`, and whether the private key matches. Public data only; no key output. |
| `tools/hudiy-autobox-check.sh` | Read a HUDIY installation's autobox configuration, look for an attached dongle (`0x1314:0x1520` / `0x1314:0x1521`), and state which MFi path is currently in use. |

Example, run against the identity that ships in the DiPlay APK (same CarlinKit provenance):

```
$ tools/dongle-mfi-profile.py /tmp/mfi
== /tmp/mfi
  subject: C=US, O=Apple Inc., OU=Apple Accessories, CN=IPA_24ACBB48646F8077F7463523085B60D2
  issuer:  C=US, O=Apple Inc., OU=Apple Certification Authority, CN=Apple Accessories Certification Authority - 00000002
  serial:  24ACBB48646F8077F7463523085B60D2
  sha256:  58d50d668e5fb0a249dfcec0997019b8d28db3afcc3b6dad31ae1cf41e895a16
  valid until: Dec 31 23:59:59 2049 GMT
  apple mfi marker (1.2.840.113635.100.6.36): present
  key matches certificate: yes
```

```
$ tools/hudiy-autobox-check.sh
HUDIY home: /home/pi/.hudiy
  installed: yes
  oemName: Hudiy
  autoWirelessConnection: True
  allowed dongle: usb 0x1314:0x1520
  allowed dongle: usb 0x1314:0x1521

attached Autobox dongles:
  1314:1520 …
MFi path: the dongle. Its firmware holds the accessory identity …
```

## 4. If the goal is CarPlay without a dongle

That is a native CarPlay accessory, and it needs more than MFi:

| Layer | Today |
| --- | --- |
| iAP2 AccAuthentication `0xAA00–0xAA05` | `libmfi` (`mfi_iap2_authenticate`) |
| AirPlay `/auth-setup` MFiSAP v1 | `libmfi` (`mfi_sap_handle`) |
| MFi4 mutual authentication | LIVI's `livi-cp/src/mfi4` (verified on a real iPhone, `spec/06 §3.3`) |
| AirPlay session, HID, video/audio | LIVI (`spec/06`) |
| Identity, USB carkit plumbing | identity files + `usbmuxd` / BlueZ |

So the practical dongle-free route is the LIVI setup already verified here, not a HUDIY plugin.
What HUDIY could add someday is vendor-side; neither its docs nor its API proto expose a hook.

## 5. Status of this integration

- Verified here: both tools run correctly, including directory, raw-blob and tar inputs, and the
  HUDIY default configuration from their repository.
- Not verified here: a physical CPC200 dongle and a HUDIY installation (HUDIY is proprietary and
  Linux-only, this host is macOS). The dongle branches in `hudiy-autobox-check.sh` use the USB IDs
  from HUDIY's own published configuration and were exercised only in the "not attached" case.
- No HUDIY code or assets are copied into this repository; the API proto and configuration are
  referenced, not vendored.
