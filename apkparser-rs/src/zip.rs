//! Lenient ZIP/APK archive reading (mirrors apkparser.zip).
//!
//! Unlike the strict `zip` crate / Python `zipfile`, we **do not validate** Extra Field
//! TLV records (except ZIP64 extra ID `0x0001` when sizes are `0xFFFFFFFF`). Malware
//! (e.g. Octo2) often fills the Extra Field with junk that makes declared Header ID /
//! size inconsistent with the Extra Field length, while Android still installs the APK.
//! See: https://hatching.io/blog/triage-insights-ep4/

use std::collections::HashMap;
use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::DeflateDecoder;
use memchr::memmem;

use crate::error::{BrokenAPKError, Error, Result};
use crate::zip64::{apply_zip64_extra, resolve_zip64_cd};

const PK_EOCD: &[u8; 4] = b"\x50\x4b\x05\x06";
const PK_CENTRAL: &[u8; 4] = b"\x50\x4b\x01\x02";
const PK_LOCAL: &[u8; 4] = b"\x50\x4b\x03\x04";

/// Max ZIP comment length + EOCD fixed size — EOCD must lie in this suffix.
const EOCD_SEARCH_WINDOW: usize = 65_535 + 22;

/// Central-directory entry metadata (sizes may be widened by ZIP64).
#[derive(Debug, Clone)]
pub struct CentralEntry {
    pub compression_method: u16,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_header_offset: u64,
    pub filename: String,
}

/// Central-directory metadata only. No entry bytes are inflated until [`ZipIndex::read`].
pub struct ZipIndex<'a> {
    data: &'a [u8],
    entries: Vec<CentralEntry>,
    by_name: HashMap<String, usize>,
    cd_off: usize,
    cd_end: usize,
}

impl<'a> ZipIndex<'a> {
    /// Parse the central directory; do not extract entry contents.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let (cd_size, cd_off) = find_eocd(data)?;
        let cd_off = cd_off as usize;
        let cd_end = cd_off.saturating_add(cd_size as usize).min(data.len());
        let entries = parse_central_directory(data, cd_off)?;
        let mut by_name = HashMap::with_capacity(entries.len());
        for (i, e) in entries.iter().enumerate() {
            by_name.insert(e.filename.clone(), i);
        }
        Ok(Self {
            data,
            entries,
            by_name,
            cd_off,
            cd_end,
        })
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn entries(&self) -> &[CentralEntry] {
        &self.entries
    }

    /// `(cd_off, cd_end)` byte range of the central directory in `data`.
    pub fn central_directory_range(&self) -> Option<(usize, usize)> {
        if self.cd_off < self.cd_end {
            Some((self.cd_off, self.cd_end))
        } else {
            None
        }
    }

    pub fn namelist(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.filename.as_str())
    }

    pub fn entry(&self, name: &str) -> Option<&CentralEntry> {
        self.by_name.get(name).map(|&i| &self.entries[i])
    }

    /// Extract one entry using the existing lenient/tampered-APK logic.
    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let e = self
            .entry(name)
            .ok_or_else(|| Error::FileNotPresent(name.to_string()))?;
        self.read_entry(e)
    }

    pub fn read_entry(&self, e: &CentralEntry) -> Result<Vec<u8>> {
        extract_entry(self.data, e)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }
}

/// ZIP archive wrapper: list names and read file contents (eager materialisation).
pub struct ZipEntry {
    names: Vec<String>,
    contents: HashMap<String, Vec<u8>>,
}

impl ZipEntry {
    /// Parse APK bytes and build file list + contents (like Python ZipEntry.parse).
    /// Implemented as [`ZipIndex::parse`] followed by extracting every entry.
    pub fn parse(apk: &[u8]) -> Result<Self> {
        let index = ZipIndex::parse(apk)?;
        let mut names = Vec::with_capacity(index.entries.len());
        let mut contents = HashMap::with_capacity(index.entries.len());
        for entry in &index.entries {
            let data = index.read_entry(entry)?;
            names.push(entry.filename.clone());
            contents.insert(entry.filename.clone(), data);
        }
        Ok(Self { names, contents })
    }

    pub fn namelist(&self) -> &[String] {
        &self.names
    }

    pub fn read(&self, name: &str) -> Result<&[u8]> {
        self.contents
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| Error::FileNotPresent(name.to_string()))
    }

    pub fn read_to_vec(&self, name: &str) -> Result<Vec<u8>> {
        self.contents
            .get(name)
            .cloned()
            .ok_or_else(|| Error::FileNotPresent(name.to_string()))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.contents.contains_key(name)
    }
}

/// Locate EOCD; return `(cd_size, cd_offset)` (possibly resolved via ZIP64).
fn find_eocd(data: &[u8]) -> Result<(u64, u64)> {
    let len = data.len();
    if len < 22 {
        return Err(BrokenAPKError("File too short for EOCD".into()).into());
    }
    let window_start = len.saturating_sub(EOCD_SEARCH_WINDOW);
    let window = &data[window_start..];

    // 1) Strict: EOCD whose 22 + comment_len reaches exactly EOF.
    for rel in memmem::rfind_iter(window, PK_EOCD) {
        let pos = window_start + rel;
        if pos + 22 > len {
            continue;
        }
        let comment_len = u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
        if pos + 22 + comment_len == len {
            return eocd_cd_fields(data, pos);
        }
    }

    // 2) Lenient: last EOCD signature in the window.
    if let Some(rel) = memmem::rfind(window, PK_EOCD) {
        let pos = window_start + rel;
        if pos + 22 <= len {
            return eocd_cd_fields(data, pos);
        }
    }

    Err(BrokenAPKError("EOCD signature not found".into()).into())
}

fn eocd_cd_fields(data: &[u8], eocd_pos: usize) -> Result<(u64, u64)> {
    let entries_this = u16::from_le_bytes([data[eocd_pos + 8], data[eocd_pos + 9]]);
    let entries_total = u16::from_le_bytes([data[eocd_pos + 10], data[eocd_pos + 11]]);
    let size_central = u32::from_le_bytes(data[eocd_pos + 12..eocd_pos + 16].try_into().unwrap());
    let offset_central =
        u32::from_le_bytes(data[eocd_pos + 16..eocd_pos + 20].try_into().unwrap());

    if size_central == 0xFFFF_FFFF
        || offset_central == 0xFFFF_FFFF
        || entries_this == 0xFFFF
        || entries_total == 0xFFFF
    {
        return resolve_zip64_cd(data, eocd_pos);
    }
    Ok((size_central as u64, offset_central as u64))
}

fn parse_central_directory(apk: &[u8], offset_central: usize) -> Result<Vec<CentralEntry>> {
    let mut offset = offset_central;
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
        let compressed_size32 = c.read_u32::<LittleEndian>()?;
        let uncompressed_size32 = c.read_u32::<LittleEndian>()?;
        let file_name_length = c.read_u16::<LittleEndian>()? as usize;
        let extra_field_length = c.read_u16::<LittleEndian>()? as usize;
        let file_comment_length = c.read_u16::<LittleEndian>()? as usize;
        let _disk = c.read_u16::<LittleEndian>()?;
        let _internal_attr = c.read_u16::<LittleEndian>()?;
        let _external_attr = c.read_u32::<LittleEndian>()?;
        let local_header_offset32 = c.read_u32::<LittleEndian>()?;

        let name_start = offset + 46;
        let name_end = name_start + file_name_length;
        if name_end > apk.len() {
            break;
        }
        let filename = String::from_utf8_lossy(&apk[name_start..name_end]).into_owned();
        let extra_end = name_end + extra_field_length;
        let next = extra_end + file_comment_length;
        if next > apk.len() {
            break;
        }
        let extra = &apk[name_end..extra_end];
        let (compressed_size, uncompressed_size, local_header_offset) = apply_zip64_extra(
            extra,
            compressed_size32 as u64,
            uncompressed_size32 as u64,
            local_header_offset32 as u64,
        );
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
    let mut compressed_size = c.read_u32::<LittleEndian>()? as u64;
    let mut uncompressed_size = c.read_u32::<LittleEndian>()? as u64;
    let file_name_length = c.read_u16::<LittleEndian>()? as usize;
    let extra_field_length = c.read_u16::<LittleEndian>()? as usize;

    // Prefer central directory sizes when local sizes are zero (data descriptor / evasion).
    if compressed_size == 0 || uncompressed_size == 0 {
        compressed_size = entry.compressed_size;
        uncompressed_size = entry.uncompressed_size;
    } else if compressed_size == 0xFFFF_FFFF || uncompressed_size == 0xFFFF_FFFF {
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
        _ => inflate_or_stored(compressed, stored_span, uncompressed_size as usize),
    }
}

fn inflate_or_stored(
    compressed: &[u8],
    stored_fallback: &[u8],
    uncompressed_hint: usize,
) -> Result<Vec<u8>> {
    if compressed.is_empty() {
        return Ok(stored_fallback.to_vec());
    }
    if stored_fallback.starts_with(&[0x03, 0x00, 0x08, 0x00])
        || stored_fallback.starts_with(&[0x00, 0x00, 0x08, 0x00])
        || stored_fallback.starts_with(b"dex\n")
        || stored_fallback.starts_with(b"dey\n")
    {
        if stored_fallback.len() >= uncompressed_hint && uncompressed_hint > 0 {
            return Ok(stored_fallback[..uncompressed_hint].to_vec());
        }
        if compressed.starts_with(&[0x03, 0x00, 0x08, 0x00])
            || compressed.starts_with(&[0x00, 0x00, 0x08, 0x00])
            || compressed.starts_with(b"dex\n")
            || compressed.starts_with(b"dey\n")
        {
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

    fn minimal_stored_zip() -> Vec<u8> {
        let mut z = Vec::new();
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&[20, 0]);
        z.extend_from_slice(&[0, 0]);
        z.extend_from_slice(&[0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(&[0x49, 0x86, 0x0b, 0x34]);
        z.extend_from_slice(&[2, 0, 0, 0]);
        z.extend_from_slice(&[2, 0, 0, 0]);
        z.extend_from_slice(&[5, 0]);
        z.extend_from_slice(&[0, 0]);
        z.extend_from_slice(b"a.txt");
        z.extend_from_slice(b"hi");
        let cd_off = z.len();
        z.extend_from_slice(b"PK\x01\x02");
        z.extend_from_slice(&[20, 0, 20, 0]);
        z.extend_from_slice(&[0, 0]);
        z.extend_from_slice(&[0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(&[0x49, 0x86, 0x0b, 0x34]);
        z.extend_from_slice(&[2, 0, 0, 0, 2, 0, 0, 0]);
        z.extend_from_slice(&[5, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(b"a.txt");
        let cd_size = z.len() - cd_off;
        z.extend_from_slice(b"PK\x05\x06");
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(&[1, 0, 1, 0]);
        z.extend_from_slice(&(cd_size as u32).to_le_bytes());
        z.extend_from_slice(&(cd_off as u32).to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        z
    }

    #[test]
    fn parse_minimal_stored_zip() {
        let z = minimal_stored_zip();
        let zip = ZipEntry::parse(&z).unwrap();
        assert_eq!(zip.namelist(), &["a.txt".to_string()]);
        assert_eq!(zip.read("a.txt").unwrap(), b"hi");
    }

    #[test]
    fn zip_index_lazy_matches_eager() {
        let z = minimal_stored_zip();
        let eager = ZipEntry::parse(&z).unwrap();
        let index = ZipIndex::parse(&z).unwrap();
        let names: Vec<_> = index.namelist().map(|s| s.to_string()).collect();
        assert_eq!(names, eager.namelist());
        assert_eq!(index.read("a.txt").unwrap(), eager.read("a.txt").unwrap());
    }

    #[test]
    fn find_eocd_with_comment() {
        let mut z = minimal_stored_zip();
        // Replace trailing comment length 0 with a comment.
        let comment = b"hello-comment";
        z.pop();
        z.pop();
        z.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        z.extend_from_slice(comment);
        let (cd_size, cd_off) = find_eocd(&z).unwrap();
        assert!(cd_size > 0);
        assert!(cd_off > 0);
        ZipIndex::parse(&z).unwrap();
    }

    #[test]
    fn find_eocd_truncated_errors() {
        assert!(find_eocd(&[0u8; 10]).is_err());
    }

    #[test]
    fn skip_malformed_extra_field_tlv() {
        let mut z = Vec::new();
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0x49, 0x86, 0x0b, 0x34]);
        z.extend_from_slice(&[2, 0, 0, 0, 2, 0, 0, 0]);
        z.extend_from_slice(&[5, 0]);
        z.extend_from_slice(&[8, 0]);
        z.extend_from_slice(b"a.txt");
        z.extend_from_slice(b"..m.\x00\x00\x00\x00");
        z.extend_from_slice(b"hi");
        let cd_off = z.len();
        z.extend_from_slice(b"PK\x01\x02");
        z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0x49, 0x86, 0x0b, 0x34]);
        z.extend_from_slice(&[2, 0, 0, 0, 2, 0, 0, 0]);
        z.extend_from_slice(&[5, 0, 8, 0, 0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0]);
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

    #[test]
    fn fake_eocd_in_payload_prefers_strict() {
        // Put PK\x05\x06 inside file data, then a real EOCD at the end.
        let mut z = Vec::new();
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0]);
        let payload = b"xxxxPK\x05\x06yyyy";
        z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.extend_from_slice(&[5, 0, 0, 0]);
        z.extend_from_slice(b"a.txt");
        z.extend_from_slice(payload);
        let cd_off = z.len();
        z.extend_from_slice(b"PK\x01\x02");
        z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        z.extend_from_slice(&[5, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(b"a.txt");
        let cd_size = z.len() - cd_off;
        z.extend_from_slice(b"PK\x05\x06");
        z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        z.extend_from_slice(&(cd_size as u32).to_le_bytes());
        z.extend_from_slice(&(cd_off as u32).to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        let (_sz, off) = find_eocd(&z).unwrap();
        assert_eq!(off as usize, cd_off);
    }
}
