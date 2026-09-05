//! Lenient ZIP/APK archive reading (mirrors apkparser.zip).
//!
//! Unlike the strict `zip` crate / Python `zipfile`, we **do not validate** Extra Field
//! TLV records. Malware (e.g. Octo2) often fills the Extra Field with junk that makes
//! declared Header ID / size inconsistent with the Extra Field length, while Android
//! still installs the APK. We only skip the declared `extra_field_length` bytes, matching
//! Android and the Python apkparser ZIP headers parser.
//! See: https://hatching.io/blog/triage-insights-ep4/

use std::collections::HashMap;
use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::DeflateDecoder;

use crate::error::{BrokenAPKError, Error, Result};

const PK_EOCD: &[u8; 4] = b"\x50\x4b\x05\x06";
const PK_CENTRAL: &[u8; 4] = b"\x50\x4b\x01\x02";
const PK_LOCAL: &[u8; 4] = b"\x50\x4b\x03\x04";

/// ZIP archive wrapper: list names and read file contents (mirrors ZipEntry).
pub struct ZipEntry {
    names: Vec<String>,
    contents: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone)]
struct CentralEntry {
    compression_method: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
    filename: String,
}

impl ZipEntry {
    /// Parse APK bytes and build file list + contents (like Python ZipEntry.parse).
    /// Extra Field bytes are skipped by declared length — no TLV validation.
    pub fn parse(apk: &[u8]) -> Result<Self> {
        let entries = parse_central_directory(apk)?;
        let mut names = Vec::with_capacity(entries.len());
        let mut contents = HashMap::with_capacity(entries.len());
        for entry in entries {
            let data = extract_entry(apk, &entry)?;
            names.push(entry.filename.clone());
            contents.insert(entry.filename, data);
        }
        Ok(Self { names, contents })
    }

    /// Return list of file names (like namelist()).
    pub fn namelist(&self) -> &[String] {
        &self.names
    }

    /// Read file by name (like zip.read(filename)).
    pub fn read(&self, name: &str) -> Result<&[u8]> {
        self.contents
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| Error::FileNotPresent(name.to_string()))
    }

    /// Read file by name into owned bytes.
    pub fn read_to_vec(&self, name: &str) -> Result<Vec<u8>> {
        self.contents
            .get(name)
            .cloned()
            .ok_or_else(|| Error::FileNotPresent(name.to_string()))
    }

    /// Check if a file exists.
    pub fn contains(&self, name: &str) -> bool {
        self.contents.contains_key(name)
    }
}

/// Locate EOCD whose record (22 bytes + comment) extends to EOF.
fn find_eocd(data: &[u8]) -> Result<(u32, u32)> {
    let len = data.len();
    if len < 22 {
        return Err(BrokenAPKError("File too short for EOCD".into()).into());
    }
    let mut pos = len.saturating_sub(22);
    while pos > 0 {
        if data[pos..].starts_with(PK_EOCD) && pos + 22 <= len {
            let comment_len =
                u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
            if pos + 22 + comment_len == len {
                let size_central =
                    u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap());
                let offset_central =
                    u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap());
                return Ok((size_central, offset_central));
            }
        }
        pos = pos.saturating_sub(1);
    }
    // Fallback: last EOCD signature (Python zipfile / older scanners).
    let mut pos = len.saturating_sub(22);
    while pos > 0 {
        if data[pos..].starts_with(PK_EOCD) && pos + 22 <= len {
            let size_central =
                u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap());
            let offset_central =
                u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap());
            return Ok((size_central, offset_central));
        }
        pos = pos.saturating_sub(1);
    }
    Err(BrokenAPKError("EOCD signature not found".into()).into())
}

fn parse_central_directory(apk: &[u8]) -> Result<Vec<CentralEntry>> {
    let (_size_central, offset_central) = find_eocd(apk)?;
    let mut offset = offset_central as usize;
    if offset + 4 > apk.len() || &apk[offset..offset + 4] != PK_CENTRAL {
        return Err(BrokenAPKError("No Central Dir at specified offset".into()).into());
    }
    let mut entries = Vec::new();
    while offset + 46 <= apk.len() {
        if &apk[offset..offset + 4] != PK_CENTRAL {
            break;
        }
        let mut c = Cursor::new(&apk[offset + 4..]);
        let _version_made = c.read_u16::<LittleEndian>()?;
        let _version_needed = c.read_u16::<LittleEndian>()?;
        let _flags = c.read_u16::<LittleEndian>()?;
        let compression_method = c.read_u16::<LittleEndian>()?;
        let _mtime = c.read_u16::<LittleEndian>()?;
        let _mdate = c.read_u16::<LittleEndian>()?;
        let _crc = c.read_u32::<LittleEndian>()?;
        let compressed_size = c.read_u32::<LittleEndian>()?;
        let uncompressed_size = c.read_u32::<LittleEndian>()?;
        let file_name_length = c.read_u16::<LittleEndian>()? as usize;
        let extra_field_length = c.read_u16::<LittleEndian>()? as usize;
        let file_comment_length = c.read_u16::<LittleEndian>()? as usize;
        let _disk = c.read_u16::<LittleEndian>()?;
        let _internal_attr = c.read_u16::<LittleEndian>()?;
        let _external_attr = c.read_u32::<LittleEndian>()?;
        let local_header_offset = c.read_u32::<LittleEndian>()?;

        let name_start = offset + 46;
        let name_end = name_start + file_name_length;
        if name_end > apk.len() {
            break;
        }
        let filename = String::from_utf8_lossy(&apk[name_start..name_end]).into_owned();
        // Skip Extra Field + comment as opaque bytes (do NOT parse TLV).
        let next = name_end + extra_field_length + file_comment_length;
        if next > apk.len() {
            break;
        }
        entries.push(CentralEntry {
            compression_method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            filename,
        });
        offset = next;
    }
    Ok(entries)
}

fn extract_entry(apk: &[u8], entry: &CentralEntry) -> Result<Vec<u8>> {
    let off = entry.local_header_offset as usize;
    if off + 30 > apk.len() || &apk[off..off + 4] != PK_LOCAL {
        return Err(Error::Parse(format!(
            "local header missing for {}",
            entry.filename
        )));
    }
    let mut c = Cursor::new(&apk[off + 4..]);
    let _version_needed = c.read_u16::<LittleEndian>()?;
    let _flags = c.read_u16::<LittleEndian>()?;
    let compression_method = c.read_u16::<LittleEndian>()?;
    let _mtime = c.read_u16::<LittleEndian>()?;
    let _mdate = c.read_u16::<LittleEndian>()?;
    let _crc = c.read_u32::<LittleEndian>()?;
    let mut compressed_size = c.read_u32::<LittleEndian>()?;
    let mut uncompressed_size = c.read_u32::<LittleEndian>()?;
    let file_name_length = c.read_u16::<LittleEndian>()? as usize;
    let extra_field_length = c.read_u16::<LittleEndian>()? as usize;

    // Prefer central directory sizes when local sizes are zero (data descriptor / evasion).
    if compressed_size == 0 || uncompressed_size == 0 {
        compressed_size = entry.compressed_size;
        uncompressed_size = entry.uncompressed_size;
    }

    let data_start = off + 30 + file_name_length + extra_field_length;
    if data_start > apk.len() {
        return Err(Error::Parse(format!(
            "truncated local entry for {}",
            entry.filename
        )));
    }

    // Prefer CD method when local method is non-standard (evasion: junk method IDs).
    let method = match compression_method {
        0 | 8 => compression_method,
        _ => match entry.compression_method {
            0 | 8 => entry.compression_method,
            _ => compression_method,
        },
    };

    let end_c = (data_start + compressed_size as usize).min(apk.len());
    let end_u = (data_start + uncompressed_size as usize).min(apk.len());
    let compressed = &apk[data_start..end_c];
    let stored_span = &apk[data_start..end_u.max(end_c)];

    match method {
        0 => Ok(stored_span.to_vec()),
        8 => inflate_or_stored(compressed, stored_span, uncompressed_size as usize),
        _ if compressed_size == uncompressed_size => Ok(stored_span.to_vec()),
        _ => {
            // Tampered compression method (Octo2-style): junk method IDs + mismatched
            // compressed_size vs uncompressed_size. Prefer inflate; if that yields nothing
            // useful, treat as stored using uncompressed_size (STORED_TAMPERED).
            inflate_or_stored(compressed, stored_span, uncompressed_size as usize)
        }
    }
}

/// Raw inflate; fall back to stored bytes when inflate fails or is empty.
/// Matches Python apkparser `extract_file_based_on_header_info` DEFLATED_TAMPERED / STORED_TAMPERED,
/// plus rejection of empty inflate success on non-deflate payloads (AXML/DEX magic).
fn inflate_or_stored(
    compressed: &[u8],
    stored_fallback: &[u8],
    uncompressed_hint: usize,
) -> Result<Vec<u8>> {
    if compressed.is_empty() {
        return Ok(stored_fallback.to_vec());
    }
    // Already looks like Android binary XML / DEX — common when method field is junk
    // and compressed_size is undersized (Octo2: read uncompressed_size instead).
    if stored_fallback.starts_with(&[0x03, 0x00, 0x08, 0x00])
        || stored_fallback.starts_with(&[0x00, 0x00, 0x08, 0x00])
        || stored_fallback.starts_with(b"dex\n")
        || stored_fallback.starts_with(b"dey\n")
    {
        // Prefer the longer span when AXML/DEX header size matches uncompressed_hint.
        if stored_fallback.len() >= uncompressed_hint && uncompressed_hint > 0 {
            return Ok(stored_fallback[..uncompressed_hint].to_vec());
        }
        if compressed.starts_with(&[0x03, 0x00, 0x08, 0x00])
            || compressed.starts_with(&[0x00, 0x00, 0x08, 0x00])
            || compressed.starts_with(b"dex\n")
            || compressed.starts_with(b"dey\n")
        {
            // Undersized compressed_size alone — still better than empty inflate.
            if stored_fallback.len() > compressed.len() {
                return Ok(stored_fallback.to_vec());
            }
            return Ok(compressed.to_vec());
        }
        return Ok(stored_fallback.to_vec());
    }
    let mut decoder = DeflateDecoder::new(compressed);
    let mut out = Vec::with_capacity(uncompressed_hint);
    match decoder.read_to_end(&mut out) {
        Ok(_) if !out.is_empty() => Ok(out),
        _ => Ok(stored_fallback.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_stored_zip() {
        // Minimal ZIP with one stored file "a.txt" = "hi"
        // Built by hand for unit test.
        let mut z = Vec::new();
        // Local header
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&[20, 0]); // version
        z.extend_from_slice(&[0, 0]); // flags
        z.extend_from_slice(&[0, 0]); // stored
        z.extend_from_slice(&[0, 0, 0, 0]); // time/date
        z.extend_from_slice(&[0x49, 0x86, 0x0b, 0x34]); // crc of "hi" approximate - we don't check
        z.extend_from_slice(&[2, 0, 0, 0]); // comp size
        z.extend_from_slice(&[2, 0, 0, 0]); // uncomp size
        z.extend_from_slice(&[5, 0]); // name len
        z.extend_from_slice(&[0, 0]); // extra len
        z.extend_from_slice(b"a.txt");
        z.extend_from_slice(b"hi");
        let local_end = z.len();
        // Central directory
        let cd_off = z.len();
        z.extend_from_slice(b"PK\x01\x02");
        z.extend_from_slice(&[20, 0, 20, 0]); // versions
        z.extend_from_slice(&[0, 0]); // flags
        z.extend_from_slice(&[0, 0]); // stored
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(&[0x49, 0x86, 0x0b, 0x34]);
        z.extend_from_slice(&[2, 0, 0, 0, 2, 0, 0, 0]);
        z.extend_from_slice(&[5, 0, 0, 0, 0, 0]); // name, extra, comment
        z.extend_from_slice(&[0, 0, 0, 0]); // disk, internal
        z.extend_from_slice(&[0, 0, 0, 0]); // external
        z.extend_from_slice(&[0, 0, 0, 0]); // local offset
        z.extend_from_slice(b"a.txt");
        let cd_size = z.len() - cd_off;
        // EOCD
        z.extend_from_slice(b"PK\x05\x06");
        z.extend_from_slice(&[0, 0, 0, 0]); // disks
        z.extend_from_slice(&[1, 0, 1, 0]); // entries
        z.extend_from_slice(&(cd_size as u32).to_le_bytes());
        z.extend_from_slice(&(cd_off as u32).to_le_bytes());
        z.extend_from_slice(&[0, 0]); // comment
        let _ = local_end;
        let zip = ZipEntry::parse(&z).unwrap();
        assert_eq!(zip.namelist(), &["a.txt".to_string()]);
        assert_eq!(zip.read("a.txt").unwrap(), b"hi");
    }

    #[test]
    fn skip_malformed_extra_field_tlv() {
        // Extra field declared length 8, content is junk (not a valid TLV) — must still extract.
        let mut z = Vec::new();
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0x49, 0x86, 0x0b, 0x34]);
        z.extend_from_slice(&[2, 0, 0, 0, 2, 0, 0, 0]);
        z.extend_from_slice(&[5, 0]); // name len
        z.extend_from_slice(&[8, 0]); // extra len = 8 (junk TLV)
        z.extend_from_slice(b"a.txt");
        z.extend_from_slice(b"..m.\x00\x00\x00\x00"); // junk extra
        z.extend_from_slice(b"hi");
        let cd_off = z.len();
        z.extend_from_slice(b"PK\x01\x02");
        z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0x49, 0x86, 0x0b, 0x34]);
        z.extend_from_slice(&[2, 0, 0, 0, 2, 0, 0, 0]);
        z.extend_from_slice(&[5, 0, 8, 0, 0, 0]); // name, extra=8, comment=0
        z.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0]); // local offset 0
        z.extend_from_slice(b"a.txt");
        z.extend_from_slice(b"..m.\x00\x00\x00\x00");
        let cd_size = z.len() - cd_off;
        z.extend_from_slice(b"PK\x05\x06");
        z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        z.extend_from_slice(&(cd_size as u32).to_le_bytes());
        z.extend_from_slice(&(cd_off as u32).to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        let zip = ZipEntry::parse(&z).unwrap();
        assert_eq!(zip.read("a.txt").unwrap(), b"hi");
    }
}
