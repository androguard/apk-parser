//! Debug signing key material (RSA-2048).

use rand::rngs::OsRng;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, PKCS_RSA_SHA256};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;

use super::{KeystoreMaterial, SignError, SignResult};

/// RSA-2048 debug key, cached under `~/.cache/apk-patch/` so rebuilds share a cert.
///
/// ECDSA alone is not enough: Android verifies the APK against every SDK from the
/// manifest `minSdkVersion` upward, so low-minSdk apps need RSA.
pub fn generate_debug_keystore() -> SignResult<KeystoreMaterial> {
    let cache = debug_key_cache_path();
    if let Ok(bytes) = std::fs::read(&cache) {
        if let Ok(mat) = deserialize_keystore(&bytes) {
            return Ok(mat);
        }
    }

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
        .map_err(|e| SignError::Signing(format!("RSA generate: {e}")))?;
    let key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| SignError::Signing(format!("RSA PKCS8: {e}")))?;
    let key_pair = KeyPair::from_pkcs8_pem_and_sign_algo(key_pem.as_str(), &PKCS_RSA_SHA256)
        .map_err(|e| SignError::Signing(format!("rcgen KeyPair: {e}")))?;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::NoCa;
    params
        .distinguished_name
        .push(DnType::CommonName, "Android Debug");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ];

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| SignError::Signing(format!("self_signed: {e}")))?;

    let mat = KeystoreMaterial {
        private_key_der: key_pair.serialize_der(),
        certificate_der: cert.der().to_vec(),
        is_ec: false,
    };

    if let Some(parent) = cache.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&cache, serialize_keystore(&mat));
    Ok(mat)
}

fn debug_key_cache_path() -> std::path::PathBuf {
    let base = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join(".cache/apk-patch/debug-signing.key")
}

fn serialize_keystore(mat: &KeystoreMaterial) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(mat.private_key_der.len() as u32).to_le_bytes());
    out.extend_from_slice(&mat.private_key_der);
    out.extend_from_slice(&(mat.certificate_der.len() as u32).to_le_bytes());
    out.extend_from_slice(&mat.certificate_der);
    out.push(u8::from(mat.is_ec));
    out
}

fn deserialize_keystore(bytes: &[u8]) -> SignResult<KeystoreMaterial> {
    if bytes.len() < 9 {
        return Err(SignError::Signing("cached keystore too short".into()));
    }
    let mut o = 0usize;
    let pk_len = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    if o + pk_len + 4 > bytes.len() {
        return Err(SignError::Signing("cached keystore truncated".into()));
    }
    let private_key_der = bytes[o..o + pk_len].to_vec();
    o += pk_len;
    let cert_len = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    if o + cert_len + 1 > bytes.len() {
        return Err(SignError::Signing("cached keystore cert truncated".into()));
    }
    let certificate_der = bytes[o..o + cert_len].to_vec();
    o += cert_len;
    let is_ec = bytes[o] != 0;
    Ok(KeystoreMaterial {
        private_key_der,
        certificate_der,
        is_ec,
    })
}
