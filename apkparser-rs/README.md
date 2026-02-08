# apkparser (Rust)

Rust port of the Python `apkparser` library. Parses Android APK files: signature (v1/JAR, v2, v3), ZIP contents, manifest (AXML), and permissions.

## Layout

- **`Cargo.toml`** – Crate root (all Rust code under `apkparser-rs/`).
- **`src/`**
  - `lib.rs` – Re-exports and public API.
  - `error.rs` – `Error`, `BrokenAPKError`, `Result`, `FileNotPresent`.
  - `utils.rs` – `is_android_raw`, `is_android`, `read_uint32_le`.
  - `zip.rs` – `ZipEntry`: parse APK as ZIP, `namelist()`, `read(name)`.
  - `signature/` – APK signature (v1, v2, v3): `ApkSignature`, signers, certs, public keys.
  - `manifest.rs` – Parse binary AndroidManifest.xml (axmldecoder): package, permissions, min/target SDK.
  - `permissions.rs` – Load AOSP permissions JSON by API level, `Permissions` helper.
  - `apk.rs` – Main `Apk` struct and `ApkOptions` (AXML, SIGNATURE, PERMISSION).
  - `main.rs` – CLI binary to inspect APK files from the command line.
- **`tests/`** – Integration tests (signature_tests.rs, apk_original_tests.rs). Test data: `../tests/data/APK/` (repo root).

## Usage

```rust
use apkparser::{Apk, ApkOptions};

let apk = std::fs::read("app.apk")?;
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

A command-line tool is included to test the library on APK files:

```bash
cd apkparser-rs
cargo build --bin apkparser
# or
cargo run --bin apkparser -- path/to/app.apk
```

**Options:**

| Option | Description |
|--------|-------------|
| `APK...` | One or more APK file path(s) |
| `--axml` / `--no-axml` | Parse AndroidManifest.xml (default: true) |
| `--signature` / `--no-signature` | Parse v1/v2/v3 signature (default: true) |
| `--permission` | Load AOSP permissions (needs aosp_permissions data) |
| `-l, --list-files` | List all entries inside the APK |
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
