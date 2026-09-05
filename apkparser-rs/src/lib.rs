//! APK parser - Rust port of apkparser (signature, zip, utils, permissions, manifest).

pub mod apk;
pub mod apkm;
pub mod error;
pub mod manifest;
pub mod permissions;
pub mod sign;
pub mod signature;
pub mod utils;
pub mod zip;
pub mod zip_write;

pub use apk::{Apk, ApkOptions};
pub use sign::{
    align_and_sign, deserialize_debug_keystore, sign_apk, serialize_debug_keystore, zipalign,
    KeystoreMaterial, SignError, SignOptions,
};
pub use zip_write::{ApkWriter, Compression, should_compress};
pub use apkm::{looks_like_apkm, unwrap_to_apk_bytes, ApkmArchive, ApkmEntry, ApkmEntryKind};
pub use error::{BrokenAPKError, Error, Result};
pub use manifest::{parse_manifest, AndroidManifest};
pub use permissions::{load_permissions, PermissionInfo, Permissions, PermissionsMap};
pub use signature::ApkSignature;
pub use utils::{is_android, is_android_raw, read_uint32_le};
pub use zip::ZipEntry;
