use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::advisory::{OsvRecord, Vuln};
use super::package::Package;

const CACHE_SCHEMA: u32 = 2;
const MAX_CACHE_FILE_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Time source, injected so freshness is testable without waiting.
pub trait Clock {
    fn now(&self) -> SystemTime;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[derive(Serialize, Deserialize)]
struct Entry {
    schema: u32,
    ecosystem: String,
    name: String,
    version: String,
    fetched_at: u64,
    vulns: Vec<Vuln>,
}

#[derive(Serialize, Deserialize)]
struct RecordEntry {
    schema: u32,
    id: String,
    fetched_at: u64,
    record: OsvRecord,
}

/// One JSON file per (ecosystem, name, version), and one per advisory record, under `dir`. The file name is a hash of the
/// key, so a hostile package name can never reach outside `dir`, and the cache never deletes:
/// a stale or damaged entry is ignored and overwritten by the next fetch.
pub struct Cache {
    dir: PathBuf,
    ttl: Duration,
    clock: Box<dyn Clock>,
}

impl Cache {
    pub fn new(dir: PathBuf, ttl: Duration, clock: Box<dyn Clock>) -> Self {
        Self { dir, ttl, clock }
    }

    fn path(&self, key: &str) -> PathBuf {
        let hex: String = Sha256::digest(key.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        self.dir.join(format!("{hex}.json"))
    }

    fn package_path(&self, p: &Package) -> PathBuf {
        self.path(&format!(
            "{}\0{}\0{}",
            p.ecosystem.osv_name(),
            p.name,
            p.version
        ))
    }

    fn record_path(&self, id: &str) -> PathBuf {
        self.path(&format!("record\0{id}"))
    }

    fn now_secs(&self) -> u64 {
        self.clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn is_fresh(&self, fetched_at: u64) -> bool {
        self.now_secs()
            .checked_sub(fetched_at)
            .is_some_and(|age| age < self.ttl.as_secs())
    }

    fn load(path: &Path) -> Option<String> {
        let meta = fs::symlink_metadata(path).ok()?;
        if !meta.is_file() || meta.len() > MAX_CACHE_FILE_BYTES {
            return None;
        }
        let mut text = String::new();
        fs::File::open(path).ok()?.read_to_string(&mut text).ok()?;
        Some(text)
    }

    /// Writes through a uniquely named temp file in the same directory, so two scans filling the
    /// cache at once never share a half-written file. A failed write is ignored: the cache only
    /// saves a lookup.
    fn store(&self, path: &Path, text: &str) {
        let _ = fs::create_dir_all(&self.dir).and_then(|()| {
            let mut tmp = tempfile::NamedTempFile::new_in(&self.dir)?;
            tmp.write_all(text.as_bytes())?;
            tmp.persist(path).map_err(|e| e.error)?;
            Ok(())
        });
    }

    /// The advisories cached for `p`, only while the entry is younger than the TTL. A missing,
    /// stale, future-dated, damaged, foreign or newer-schema file is `None`.
    pub fn get(&self, p: &Package) -> Option<Vec<Vuln>> {
        let entry: Entry = serde_json::from_str(&Self::load(&self.package_path(p))?).ok()?;
        let same_key = entry.ecosystem == p.ecosystem.osv_name()
            && entry.name == p.name
            && entry.version == p.version;
        (entry.schema == CACHE_SCHEMA && same_key && self.is_fresh(entry.fetched_at))
            .then_some(entry.vulns)
    }

    pub fn put(&self, p: &Package, vulns: &[Vuln]) {
        let entry = Entry {
            schema: CACHE_SCHEMA,
            ecosystem: p.ecosystem.osv_name().to_owned(),
            name: p.name.clone(),
            version: p.version.clone(),
            fetched_at: self.now_secs(),
            vulns: vulns.to_vec(),
        };
        if let Ok(text) = serde_json::to_string(&entry) {
            self.store(&self.package_path(p), &text);
        }
    }

    /// The advisory record cached for `id`, under the same freshness rules as `get`. It lets a
    /// lookup that ran out of time resume where it stopped.
    pub fn get_record(&self, id: &str) -> Option<OsvRecord> {
        let entry: RecordEntry = serde_json::from_str(&Self::load(&self.record_path(id))?).ok()?;
        (entry.schema == CACHE_SCHEMA && entry.id == id && self.is_fresh(entry.fetched_at))
            .then_some(entry.record)
    }

    pub fn put_record(&self, record: &OsvRecord) {
        let entry = RecordEntry {
            schema: CACHE_SCHEMA,
            id: record.id.clone(),
            fetched_at: self.now_secs(),
            record: record.clone(),
        };
        if let Ok(text) = serde_json::to_string(&entry) {
            self.store(&self.record_path(&record.id), &text);
        }
    }
}
