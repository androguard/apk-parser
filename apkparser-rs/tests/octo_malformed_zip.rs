//! Debug / regression: Octo2-style malformed APK (extra-field junk + tampered methods).

use apkparser::{parse_manifest, ZipEntry};

#[test]
fn octo2_sample_extracts_manifest() {
    let p = "/Users/toto/Downloads/9188452fc54aeb560e24465b809de3958fbdaa16377f017fe7c344721dcc6305";
    if !std::path::Path::new(p).exists() {
        return;
    }
    let data = std::fs::read(p).unwrap();
    let z = ZipEntry::parse(&data).unwrap();
    assert!(z.contains("AndroidManifest.xml"));
    let m = z.read("AndroidManifest.xml").unwrap();
    assert!(
        m.len() > 100,
        "manifest too short: {} magic={:02x?}",
        m.len(),
        &m[..m.len().min(8)]
    );
    assert_eq!(&m[..4], &[0x03, 0x00, 0x08, 0x00]);
    let parsed = parse_manifest(m).expect("parse AXML");
    assert!(parsed.package.is_some(), "package missing: {:?}", parsed);
}
