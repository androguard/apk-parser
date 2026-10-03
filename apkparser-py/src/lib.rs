//! Python bindings for apkparser-rs (central-directory ZIP + APK).

use apkparser::{Apk, ApkOptions, ZipArchive};
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyType;
use std::path::Path;

fn apk_err(e: apkparser::Error) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Lazy ZIP: central directory only; inflate on `read`.
#[pyclass(name = "ZipArchive", unsendable)]
struct PyZipArchive {
    inner: ZipArchive,
}

#[pymethods]
impl PyZipArchive {
    #[new]
    fn new(data: Vec<u8>) -> PyResult<Self> {
        Ok(Self {
            inner: ZipArchive::parse(data).map_err(apk_err)?,
        })
    }

    #[classmethod]
    fn from_path(_cls: &Bound<'_, PyType>, path: String) -> PyResult<Self> {
        let data = std::fs::read(&path).map_err(|e| PyIOError::new_err(e.to_string()))?;
        Self::new(data)
    }

    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, PyType>, data: Vec<u8>) -> PyResult<Self> {
        Self::new(data)
    }

    fn namelist(&self) -> Vec<String> {
        self.inner.names()
    }

    fn contains(&self, name: &str) -> bool {
        self.inner.contains(name)
    }

    fn read(&self, name: &str) -> PyResult<Vec<u8>> {
        self.inner.read(name).map_err(apk_err)
    }

    fn __len__(&self) -> usize {
        self.inner.entries().len()
    }

    fn __repr__(&self) -> String {
        format!("<ZipArchive files={}>", self.inner.entries().len())
    }
}

/// Rust APK parser (CD-only zip, on-demand extract).
#[pyclass(name = "Apk", unsendable)]
struct PyApk {
    inner: Apk,
}

#[pymethods]
impl PyApk {
    #[new]
    #[pyo3(signature = (path, axml=true, signature=true, permission=true))]
    fn from_path(path: String, axml: bool, signature: bool, permission: bool) -> PyResult<Self> {
        let opts = ApkOptions::default()
            .with_axml(axml)
            .with_signature(signature)
            .with_permission(permission);
        let inner = Apk::from_path(Path::new(&path), opts).map_err(apk_err)?;
        Ok(Self { inner })
    }

    #[classmethod]
    #[pyo3(signature = (data, axml=true, signature=true, permission=true))]
    fn from_bytes(
        _cls: &Bound<'_, PyType>,
        data: Vec<u8>,
        axml: bool,
        signature: bool,
        permission: bool,
    ) -> PyResult<Self> {
        let opts = ApkOptions::default()
            .with_axml(axml)
            .with_signature(signature)
            .with_permission(permission);
        let inner = Apk::from_bytes(&data, opts).map_err(apk_err)?;
        Ok(Self { inner })
    }

    fn is_apk(&self) -> bool {
        self.inner.is_apk()
    }

    fn get_files(&self) -> Vec<String> {
        self.inner.get_files()
    }

    fn get_file(&self, name: &str) -> PyResult<Vec<u8>> {
        self.inner.get_file(name).map_err(apk_err)
    }

    fn package(&self) -> Option<String> {
        self.inner
            .get_android_manifest()
            .and_then(|m| m.package.clone())
    }

    fn is_signed(&self) -> bool {
        self.inner
            .get_signature()
            .map(|s| s.is_signed())
            .unwrap_or(false)
    }

    fn __repr__(&self) -> String {
        format!(
            "<apkparser_rs.Apk package={:?} files={}>",
            self.package(),
            self.inner.get_files().len()
        )
    }
}

#[pymodule]
fn apkparser_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyZipArchive>()?;
    m.add_class::<PyApk>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
