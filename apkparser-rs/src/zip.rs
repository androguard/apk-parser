//! ZIP/APK archive reading (mirrors apkparser.zip).

use std::collections::HashMap;
use std::io::Cursor;

use crate::error::{Error, Result};

/// ZIP archive wrapper: list names and read file contents (mirrors ZipEntry).
pub struct ZipEntry {
    names: Vec<String>,
    contents: HashMap<String, Vec<u8>>,
}

impl ZipEntry {
    /// Parse APK bytes and build file list + contents (like Python ZipEntry.parse).
    pub fn parse(apk: &[u8]) -> Result<Self> {
        let cursor = Cursor::new(apk);
        let mut archive = zip::ZipArchive::new(cursor).map_err(Error::Zip)?;
        let mut names = Vec::new();
        let mut contents = HashMap::new();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(Error::Zip)?;
            let name = file.name().to_string();
            let mut data = Vec::new();
            std::io::copy(&mut file, &mut data).map_err(Error::Io)?;
            names.push(name.clone());
            contents.insert(name, data);
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
