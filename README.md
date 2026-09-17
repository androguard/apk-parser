<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">APK-PARSER</h2>

# APK Parser: Your Crowbar for Android Archive

<div align="center">

![Powered](https://img.shields.io/badge/androguard-green?style=for-the-badge&label=Powered%20by&link=https%3A%2F%2Fgithub.com%2Fandroguard)
![Sponsor](https://img.shields.io/badge/sponsor-nlnet-blue?style=for-the-badge&link=https%3A%2F%2Fnlnet.nl%2F)
![PYPY](https://img.shields.io/badge/PYPI-APKPARSER-violet?style=for-the-badge&link=https%3A%2F%2Fpypi.org%2Fproject%2Fapkparser-ag%2F)

</div>

## Description

At its core, every APK is a fortress built on a simple foundation: the ZIP archive. apk-parser is the key to that fortress.

This is a standalone library to deconstruct Android Application Packages (APK / APKM): ZIP structure, binary `AndroidManifest.xml`, signatures (v1/v2/v3), and permissions. It is a foundational pillar of the new Androguard Ecosystem.

Available as:

- **Python** — `apkparser` (PyPI: [`apkparser-ag`](https://pypi.org/project/apkparser-ag/))
- **Rust** — [`apkparser-rs/`](./apkparser-rs/) (library + CLI)

Both use a **lenient ZIP reader** (skip Extra Field TLV validation; tolerate tampered compression methods) so malware-style APKs that still install on Android remain analyzable. See [Octo2 / Triage Insights](https://hatching.io/blog/triage-insights-ep4/).

### Philosophy

Following the "Deconstruct to Reconstruct" philosophy of the new Androguard, apk-parser has been uncoupled from the main analysis engine. It exists as an independent, lightweight, and highly portable tool. By focusing on the archive layer, it provides a stable interface for any tool that needs to peer inside an APK.

### Key Features

- **Archive parsing** — full ZIP / central directory without shelling out to `unzip`
- **File extraction** — any path (`classes.dex`, `res/`, …)
- **Manifest** — binary AXML → package, SDK levels, permissions, components
- **Signature & certificates** — v1 (JAR), v2, v3
- **APKM** — APKMirror split containers (detect, unwrap `base.apk`, list / extract splits)
- **Python + Rust** — same concepts in both languages

## Installation

### Python

```bash
git clone https://github.com/androguard/apk-parser.git
cd apk-parser
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
# or: pip install apkparser-ag
```

### Rust

```bash
cd apkparser-rs
cargo build --release
# library + CLI binary `apkparser`
```

## CLI

**Python**

```bash
apkparser -i tests/data/APK/TestActivity.apk
```

**Rust**

```bash
cd apkparser-rs
cargo run --bin apkparser -- ../tests/data/APK/TestActivity.apk --fingerprints
```

Example output (Rust CLI on the bundled test APK):

```text
=== ../tests/data/APK/TestActivity.apk ===
  kind: APK
  is_apk: true
  files: 10 entries
  manifest:
    package: tests.androguard
    versionCode: 1
    versionName: 1.0
    minSdkVersion: 9
    targetSdkVersion: 16
  signature:
    v1 (JAR): true
    v2: false
    v3: false
    v1 entry: META-INF/CERT.RSA
    v1 cert SHA-256: 6f5c31608f1f9e285eb6343c7c8af07de81c1fb2148b5349bec906444144576d
```

## Library examples

Examples use the repo test APK:

`tests/data/APK/TestActivity.apk`

### Load an APK

**Python**

```python
import io
from apkparser import APK, OPTION_AXML, OPTION_SIGNATURE, OPTION_PERMISSION

with open("tests/data/APK/TestActivity.apk", "rb") as f:
    apk = APK(
        io.BytesIO(f.read()),
        {
            OPTION_AXML: True,
            OPTION_SIGNATURE: True,
            OPTION_PERMISSION: True,
        },
    )
```

**Rust**

```rust
use apkparser::{Apk, ApkOptions};

let bytes = std::fs::read("tests/data/APK/TestActivity.apk")?;
let mut apk = Apk::from_bytes(
    &bytes,
    ApkOptions::default()
        .with_axml(true)
        .with_signature(true)
        .with_permission(true),
)?;
```

### Manifest & app metadata

**Python**

```python
>>> m = apk.get_android_manifest()
>>> m.package
'tests.androguard'
>>> m.get_min_sdk_version(), m.get_target_sdk_version()
('9', '16')
>>> m.androidversion
{'Code': '1', 'Name': '1.0'}
>>> apk.get_app_name()
'TestsAndroguardApplication'
>>> apk.get_main_activity()
'tests.androguard.TestActivity'
>>> apk.get_app_icon()
'res/drawable-hdpi/icon.png'
>>> apk.get_activities()
['tests.androguard.TestActivity']
```

**Rust**

```rust
let m = apk.get_android_manifest().unwrap();
assert_eq!(m.package.as_deref(), Some("tests.androguard"));
assert_eq!(m.min_sdk_version, Some(9));
assert_eq!(m.target_sdk_version, Some(16));
assert_eq!(m.version_code, Some(1));
assert_eq!(m.version_name.as_deref(), Some("1.0"));
// get_app_name / get_main_activity / get_app_icon are Python-only for now.
```

### Files & DEX

**Python**

```python
>>> apk.get_files()
['res/layout/main.xml', 'AndroidManifest.xml', 'resources.arsc',
 'res/drawable-hdpi/icon.png', 'res/drawable-ldpi/icon.png',
 'res/drawable-mdpi/icon.png', 'classes.dex',
 'META-INF/MANIFEST.MF', 'META-INF/CERT.SF', 'META-INF/CERT.RSA']
>>> apk.get_dex_names()
['classes.dex']
>>> apk.get_file("classes.dex")[:4]
b'dex\n'
```

**Rust**

```rust
let files = apk.get_files();
assert!(files.iter().any(|f| f == "AndroidManifest.xml"));
assert!(files.iter().any(|f| f == "classes.dex"));

let dex = apk.get_file("classes.dex")?;
assert!(dex.starts_with(b"dex\n"));
```

### Signature & certificates

**Python**

```python
>>> apk.signature.is_signed()
True
>>> apk.signature.is_signed_v1(), apk.signature.is_signed_v2(), apk.signature.is_signed_v3()
(True, False, False)
>>> apk.signature.get_signature_name()
'META-INF/CERT.RSA'
>>> import hashlib
>>> der = apk.signature.get_certificate_der(apk.signature.get_signature_name())
>>> hashlib.sha256(der).hexdigest()
'6f5c31608f1f9e285eb6343c7c8af07de81c1fb2148b5349bec906444144576d'
```

v1 + v2 sample (`tests/data/APK/TestActivity_signed_both.apk`):

```python
>>> apk.signature.is_signed_v1(), apk.signature.is_signed_v2()
(True, True)
>>> apk.signature.get_signature_name()
'META-INF/ANDROGUA.RSA'
>>> len(apk.signature.get_certificates_der_v2())
1
```

**Rust**

```rust
let sig = apk.get_signature_mut().unwrap();
assert!(sig.is_signed_v1());
assert!(!sig.is_signed_v2());
assert_eq!(sig.get_signature_name().as_deref(), Some("META-INF/CERT.RSA"));

let der = sig.get_certificate_der("META-INF/CERT.RSA")?.unwrap();
// SHA-256: 6f5c31608f1f9e285eb6343c7c8af07de81c1fb2148b5349bec906444144576d

let certs_v2 = sig.get_certificates_der_v2()?;
let certs_v3 = sig.get_certificates_der_v3()?;
```

Useful signature helpers (Python):

```text
signature.is_signed() / is_signed_v1() / is_signed_v2() / is_signed_v3()
signature.get_signature_name() / get_signature_names()
signature.get_certificate() / get_certificate_der()
signature.get_certificates_der_v2() / get_certificates_der_v3()
signature.get_public_keys_der_v2() / get_public_keys_der_v3()
```

### Permissions

**Python** (`tests/data/APK/a2dp.Vol_137.apk`)

```python
>>> apk.get_android_manifest().package
'a2dp.Vol'
>>> sorted(apk.get_android_manifest().permissions)[:3]
['android.permission.ACCESS_COARSE_LOCATION',
 'android.permission.ACCESS_FINE_LOCATION',
 'android.permission.ACCESS_LOCATION_EXTRA_COMMANDS']
>>> # With OPTION_PERMISSION:
>>> apk.permissions.get_details_permissions()
# name -> [protectionLevel, label, description]
```

**Rust**

```rust
let m = apk.get_android_manifest().unwrap();
assert_eq!(m.package.as_deref(), Some("a2dp.Vol"));
assert!(m.uses_permissions.iter().any(|p| p == "android.permission.BLUETOOTH"));

if let Some(perms) = apk.get_permissions() {
    let _aosp = perms.get_requested_aosp_permissions();
}
```

### DEX objects (Python)

```python
for dex in apk.get_all_dex():
    print(dex)
```

### APKM (split containers)

**Python**

```python
import io
from apkparser import APK, OPTION_AXML, OPTION_SIGNATURE
from apkparser.utils import is_android_raw, unwrap_apkm_to_apk_bytes

raw = open("app.apkm", "rb").read()
assert is_android_raw(raw) == "APKM"
base = unwrap_apkm_to_apk_bytes(raw)
# Or load directly — APK() auto-unwraps APKM:
apk = APK(io.BytesIO(raw), {OPTION_AXML: True, OPTION_SIGNATURE: True})
```

**Rust**

```rust
use apkparser::{looks_like_apkm, unwrap_to_apk_bytes, ApkmArchive, Apk, ApkOptions};

assert!(looks_like_apkm(&raw));
let base = unwrap_to_apk_bytes(&raw)?;
let apk = Apk::from_bytes(&raw, ApkOptions::default().with_axml(true))?;

let archive = ApkmArchive::from_bytes(&raw)?;
archive.extract_apks_to(std::path::Path::new("./out"))?;
```

```bash
cargo run --bin apkparser -- app.apkm --list-splits
cargo run --bin apkparser -- app.apkm --extract-apks ./out
```

## Python ↔ Rust map

| Python | Rust |
|--------|------|
| `apkparser.APK` / `OPTION_*` | `Apk` / `ApkOptions` |
| `apkparser.zip` | `apkparser::zip` (`ZipEntry`) |
| `apkparser.signature` | `apkparser::signature` (`ApkSignature`) |
| `apkparser.permissions` | `apkparser::permissions` |
| `apkparser.utils.is_android_raw` | `is_android_raw` |
| APKM unwrap helpers | `looks_like_apkm`, `unwrap_to_apk_bytes`, `ApkmArchive` |
| `get_app_name` / `get_main_activity` / components | Python only (for now) |
| DEX via `dexparser` | Logical DEX helpers (partial) |

More Rust detail: [`apkparser-rs/README.md`](./apkparser-rs/README.md).

## Tests

```bash
# Python
pytest tests/

# Rust
cd apkparser-rs && cargo test
```

Test APKs: `tests/data/APK/` (`TestActivity.apk`, `TestActivity_signed_both.apk`, `a2dp.Vol_137.apk`, `apksig/`, …).

## License

Distributed under the [Apache License, Version 2.0](LICENSE).
