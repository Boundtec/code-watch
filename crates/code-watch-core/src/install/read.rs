use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// Manifests and rc files; a hostile project must not make a check allocate without bound.
pub(super) const MAX_TEXT_BYTES: u64 = 1024 * 1024;
/// Lockfiles outgrow manifests; same cap as the OSV layer.
pub(super) const MAX_LOCK_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadError {
    Missing,
    TooLarge,
    Unreadable,
    NotUtf8,
}

impl ReadError {
    pub(super) fn describe(self) -> &'static str {
        match self {
            ReadError::Missing => "does not exist",
            ReadError::TooLarge => "is larger than the size limit",
            ReadError::Unreadable => "could not be read",
            ReadError::NotUtf8 => "is not valid UTF-8",
        }
    }
}

/// Reads a regular file (a symlink to one is followed, a FIFO or device is refused so the check
/// cannot hang) up to `cap` bytes. Never writes.
pub(super) fn read_text(path: &Path, cap: u64) -> Result<String, ReadError> {
    let meta = fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ReadError::Missing,
        _ => ReadError::Unreadable,
    })?;
    if !meta.is_file() {
        return Err(ReadError::Unreadable);
    }
    if meta.len() > cap {
        return Err(ReadError::TooLarge);
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(cap + 1).read_to_end(&mut bytes))
        .map_err(|_| ReadError::Unreadable)?;
    if bytes.len() as u64 > cap {
        return Err(ReadError::TooLarge);
    }
    String::from_utf8(bytes).map_err(|_| ReadError::NotUtf8)
}

/// `Ok(None)` when the file is not there, which several callers treat as normal.
pub(super) fn read_optional(path: &Path, cap: u64) -> Result<Option<String>, ReadError> {
    match read_text(path, cap) {
        Ok(text) => Ok(Some(text)),
        Err(ReadError::Missing) => Ok(None),
        Err(e) => Err(e),
    }
}
