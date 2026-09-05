# apkparser (Rust)

Rust port of the Python `apkparser` library. Parses Android APK files: signature (v1/JAR, v2, v3), ZIP contents, manifest (AXML), and permissions.

## Layout

- **`Cargo.toml`** – Crate root (all Rust code under `apkparser-rs/`).
- **`src/`**
  - `lib.rs` – Re-exports and public API.
  - `error.rs` – `Error`, `BrokenAPKError`, `Result`, `FileNotPresent`.
  - `utils.rs` – `is_android_raw`, `is_android`, `read_uint32_le`.
  - `zip.rs` – Lenient `ZipEntry` (skip Extra Field TLVs; tampered compression methods). Needed for malware APKs that break strict `zipfile`/`ZipFile` while still installing on Android ([Octo2 write-up](https://hatching.io/blog/triage-insights-ep4/)).
  - `signature/` – APK signature (v1, v2, v3): `ApkSignature`, signers, certs, public keys.
  - `manifest.rs` – Parse binary AndroidManifest.xml (axmldecoder): package, permissions, min/target SDK.
  - `permissions.rs` – Load AOSP permissions JSON by API level, `Permissions` helper.
  - `apkm.rs` – APKM (APKMirror split container): detect, list splits, extract base APK.
  - `apk.rs` – Main `Apk` struct and `ApkOptions` (AXML, SIGNATURE, PERMISSION). `Apk::from_bytes` auto-unwraps APKM → base APK.
  - `main.rs` – CLI binary to inspect APK files from the command line.
- **`tests/`** – Integration tests (signature_tests.rs, apk_original_tests.rs). Test data: `../tests/data/APK/` (repo root).

## APKM

`.apkm` files are ZIP containers (`base.apk` + `split_config.*.apk` + optional `info.json`). Detection and helpers:

```rust
use apkparser::{looks_like_apkm, unwrap_to_apk_bytes, ApkmArchive, Apk, ApkOptions};

// One-shot: get analyzable base APK bytes
let apk_bytes = unwrap_to_apk_bytes(&raw)?;

// Or open as Apk (auto-unwraps APKM)
let apk = Apk::from_bytes(&raw, ApkOptions::default().with_axml(true))?;

// Full container access
let archive = ApkmArchive::from_bytes(&raw)?;
let base = archive.base_apk_bytes()?;
let splits = archive.split_names();
archive.extract_apks_to(std::path::Path::new("./out"))?;
```

`is_android_raw` returns `"APKM"` for these containers (and `"APK"` for plain packages).

## Usage

```rust
use apkparser::{Apk, ApkOptions};

let apk = std::fs::read("app.apk")?; // or app.apkm
let mut apk = Apk::from_bytes(&apk, ApkOptions::default()
    .with_axml(true)
    .with_signature(true)
    .with_permission(true))?;

// Files
let files = apk.get_files();
let manifest_bytes = apk.get_file("AndroidManifest.xml")?;

// Parsed manifest
if let Some(m) = apk.get_android_manifest() {
    println!("package: {:?}", m.package);
    println!("permissions: {:?}", m.uses_permissions);
}

// Signature
if let Some(sig) = apk.get_signature_mut() {
    if sig.is_signed_v1() {
        let name = sig.get_signature_name().unwrap();
        let cert = sig.get_certificate_der(&name)?;
    }
    let certs_v2 = sig.get_certificates_der_v2()?;
    let certs_v3 = sig.get_certificates_der_v3()?;
}

// Permissions (when PERMISSION option set)
if let Some(perms) = apk.get_permissions() {
    let aosp = perms.get_requested_aosp_permissions();
}
```

## CLI

A command-line tool is included to test the library on APK / APKM files:

```bash
cd apkparser-rs
cargo build --bin apkparser
# or
cargo run --bin apkparser -- path/to/app.apk
cargo run --bin apkparser -- path/to/app.apkm --list-splits
cargo run --bin apkparser -- path/to/app.apkm --extract-apks ./out
```

**Options:**

| Option | Description |
|--------|-------------|
| `PACKAGE...` | One or more APK / APKM file path(s) |
| `--axml` / `--no-axml` | Parse AndroidManifest.xml (default: true) |
| `--signature` / `--no-signature` | Parse v1/v2/v3 signature (default: true) |
| `--permission` | Load AOSP permissions (needs aosp_permissions data) |
| `-l, --list-files` | List all entries inside the (base) APK |
| `--list-splits` | List APKM base + split entries |
| `--extract-apks DIR` | Extract APKM `*.apk` members to DIR |
| `--fingerprints` | Print certificate SHA-256 fingerprints |
| `-v, --verbose` | Verbose (e.g. list uses-permission) |

**Examples:**

```bash
cargo run --bin apkparser -- app.apk
cargo run --bin apkparser -- app.apk --fingerprints -l
cargo run --bin apkparser -- app.apk --no-axml --list-files
```

## Build and test

From repo root or from `apkparser-rs/`:

```bash
cd apkparser-rs
cargo build
cargo test
```

Test data is under `../tests/data/APK/` (repo root).

## Python parity

| Python              | Rust                          |
|---------------------|-------------------------------|
| `apkparser.utils`   | `apkparser::utils`            |
| `apkparser.zip`     | `apkparser::zip`              |
| `apkparser.signature` | `apkparser::signature`     |
| `apkparser.permissions` | `apkparser::permissions` |
| `APK`, `OPTION_*`   | `Apk`, `ApkOptions`           |
| AXML (axml package) | `axmldecoder` + `manifest`    |

DEX parsing and full permission details (e.g. implied permissions) are not implemented.
