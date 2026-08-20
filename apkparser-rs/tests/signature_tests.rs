//! Integration tests mirroring Python signature tests.
//! Test data: ../tests/data/APK/ (repo root)

use apkparser::{Apk, ApkOptions};
use std::path::Path;

fn test_data_dir() -> Option<std::path::PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("../tests/data/APK");
    root.canonicalize().ok()
}

#[test]
fn test_apk_v1_only_signed() {
    let dir = match test_data_dir() {
        Some(d) => d,
        None => return,
    };
    let apk_path = dir.join("TestActivity.apk");
    if !apk_path.exists() {
        return;
    }
    let apk = std::fs::read(&apk_path).unwrap();
    let mut apk = Apk::from_bytes(
        &apk,
        ApkOptions::default().with_axml(true).with_signature(true),
    )
    .unwrap();
    let sig = apk.get_signature_mut().unwrap();
    assert!(sig.is_signed_v1());
    assert!(!sig.is_signed_v2());
    assert!(sig.is_signed());
    assert_eq!(
        sig.get_certificates_der_v2().unwrap(),
        vec![] as Vec<Vec<u8>>
    );
    assert_eq!(
        sig.get_signature_name().as_deref(),
        Some("META-INF/CERT.RSA")
    );
    assert_eq!(
        sig.get_signature_names(),
        vec!["META-INF/CERT.RSA".to_string()]
    );
    let cert_der = sig
        .get_certificate_der(sig.get_signature_name().as_deref().unwrap())
        .unwrap();
    assert!(cert_der.is_some());
}

#[test]
fn test_apk_cert_der_hex() {
    let dir = match test_data_dir() {
        Some(d) => d,
        None => return,
    };
    let apk_path = dir.join("TestActivity.apk");
    if !apk_path.exists() {
        return;
    }
    let apk = std::fs::read(&apk_path).unwrap();
    let apk = Apk::from_bytes(
        &apk,
        ApkOptions::default().with_axml(true).with_signature(true),
    )
    .unwrap();
    let sig = apk.get_signature().unwrap();
    let cert_der = sig
        .get_certificate_der("META-INF/CERT.RSA")
        .unwrap()
        .expect("cert");
    let expected = "308201E53082014EA00302010202045114FECF300D06092A864886F70D010105\
05003037310B30090603550406130255533110300E060355040A1307416E6472\
6F6964311630140603550403130D416E64726F6964204465627567301E170D31\
33303230383133333430375A170D3433303230313133333430375A3037310B30\
090603550406130255533110300E060355040A1307416E64726F696431163014\
0603550403130D416E64726F696420446562756730819F300D06092A864886F7\
0D010101050003818D00308189028181009903975EC93F0F3CCB54BD1A415ECF\
3505993715B8B9787F321104ACC7397D186F01201341BCC5771BB28695318E00\
6E47C888D3C7EE9D952FF04DF06EDAB1B511F51AACDCD02E0ECF5AA7EC6B51BA\
08C601074CF2DA579BD35054E4F77BAAAAF0AA67C33C1F1C3EEE05B5862952C0\
888D39179C0EDD785BA4F47FB7DF5D5F030203010001300D06092A864886F70D\
0101050500038181006B571D685D41E77744F5ED20822AE1A14199811CE649BB\
B29248EB2F3CC7FB70F184C2A3D17C4F86B884FCA57EEB289ECB5964A1DDBCBD\
FCFC60C6B7A33D189927845067C76ED29B42D7F2C7F6E2389A4BC009C01041A3\
6E666D76D1D66467416E68659D731DC7328CB4C2E989CF59BB6D2D2756FDE7F2\
B3FB733EBB4C00FD3B";
    let hex_upper: String = hex::encode(&cert_der).to_uppercase();
    assert_eq!(hex_upper, expected.replace('\n', ""));
}

#[test]
fn test_apk_cert_fingerprints() {
    let dir = match test_data_dir() {
        Some(d) => d,
        None => return,
    };
    let apk_path = dir.join("TestActivity.apk");
    if !apk_path.exists() {
        return;
    }
    let apk = std::fs::read(&apk_path).unwrap();
    let apk = Apk::from_bytes(
        &apk,
        ApkOptions::default().with_axml(true).with_signature(true),
    )
    .unwrap();
    let sig = apk.get_signature().unwrap();
    let cert_der = sig
        .get_certificate_der("META-INF/CERT.RSA")
        .unwrap()
        .expect("cert");
    assert_eq!(md5_hash(&cert_der), "99fffc37d36487ddbaabf17f945989b5");
    assert_eq!(
        sha1_hash(&cert_der),
        "1e0be401f93460e08d89a3ef6e2725556be1d16b"
    );
    assert_eq!(
        sha256_hash(&cert_der),
        "6f5c31608f1f9e285eb6343c7c8af07de81c1fb2148b5349bec906444144576d"
    );
}

#[test]
fn test_apk_v2_signature() {
    let dir = match test_data_dir() {
        Some(d) => d,
        None => return,
    };
    let apk_path = dir.join("TestActivity_signed_both.apk");
    if !apk_path.exists() {
        return;
    }
    let apk = std::fs::read(&apk_path).unwrap();
    let mut apk = Apk::from_bytes(
        &apk,
        ApkOptions::default().with_axml(true).with_signature(true),
    )
    .unwrap();
    let sig = apk.get_signature_mut().unwrap();
    assert!(sig.is_signed_v1());
    assert!(sig.is_signed_v2());
    assert!(sig.is_signed());
    assert_eq!(
        sig.get_signature_name().as_deref(),
        Some("META-INF/ANDROGUA.RSA")
    );
    let certs_v2 = sig.get_certificates_der_v2().unwrap();
    assert_eq!(certs_v2.len(), 1);
    let cert_v1 = sig
        .get_certificate_der(sig.get_signature_name().as_deref().unwrap())
        .unwrap();
    assert!(cert_v1.is_some());
    assert_eq!(cert_v1.as_ref().unwrap(), &certs_v2[0]);
    let cert_disk = std::fs::read(dir.join("certificate.der")).unwrap();
    let cert_der_v1 = cert_v1.unwrap();
    let cert_der_v2 = &certs_v2[0];
    assert_eq!(sha256_hash(&cert_disk), sha256_hash(&cert_der_v1));
    assert_eq!(sha256_hash(&cert_disk), sha256_hash(cert_der_v2));
}

#[test]
fn test_apk_unsigned() {
    let dir = match test_data_dir() {
        Some(d) => d,
        None => return,
    };
    let apk_path = dir.join("TestActivity_unsigned.apk");
    if !apk_path.exists() {
        return;
    }
    let apk = std::fs::read(&apk_path).unwrap();
    let apk = Apk::from_bytes(
        &apk,
        ApkOptions::default().with_axml(true).with_signature(true),
    )
    .unwrap();
    let sig = apk.get_signature().unwrap();
    assert!(sig.get_signature_name().is_none());
    assert!(sig.get_signature_names().is_empty());
}

#[test]
fn test_apk_get_files_and_manifest() {
    let dir = match test_data_dir() {
        Some(d) => d,
        None => return,
    };
    let apk_path = dir.join("TestActivity.apk");
    if !apk_path.exists() {
        return;
    }
    let apk = std::fs::read(&apk_path).unwrap();
    let apk = Apk::from_bytes(
        &apk,
        ApkOptions::default().with_axml(true).with_signature(true),
    )
    .unwrap();
    let files = apk.get_files();
    assert!(files.iter().any(|f| f == "AndroidManifest.xml"));
    let manifest = apk.get_android_manifest().unwrap();
    assert_eq!(manifest.package.as_deref(), Some("tests.androguard"));
}

fn md5_hash(data: &[u8]) -> String {
    hex::encode(md5::compute(data).as_ref())
}
fn sha1_hash(data: &[u8]) -> String {
    use sha1::Digest;
    hex::encode(sha1::Sha1::digest(data))
}
fn sha256_hash(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}
