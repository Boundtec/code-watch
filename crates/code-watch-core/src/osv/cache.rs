use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::advisory::Vuln;
use super::package::Package;

const CACHE_SCHEMA: u32 = 1;
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

/// One JSON file per (ecosystem, name, version) under `dir`. The file name is a hash of the
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

    fn path(&self, p: &Package) -> PathBuf {
        let key = format!("{}\0{}\0{}", p.ecosystem.osv_name(), p.name, p.version);
        let hex: String = Sha256::digest(key.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        self.dir.join(format!("{hex}.json"))
    }

    fn now_secs(&self) -> u64 {
        self.clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// The advisories cached for `p`, only while the entry is younger than the TTL. A missing,
    /// stale, future-dated, damaged, foreign or newer-schema file is `None`.
    pub fn get(&self, p: &Package) -> Option<Vec<Vuln>> {
        let path = self.path(p);
        let meta = fs::symlink_metadata(&path).ok()?;
        if !meta.is_file() || meta.len() > MAX_CACHE_FILE_BYTES {
            return None;
        }
        let mut text = String::new();
        fs::File::open(&path).ok()?.read_to_string(&mut text).ok()?;
        let entry: Entry = serde_json::from_str(&text).ok()?;
        let same_key = entry.ecosystem == p.ecosystem.osv_name()
            && entry.name == p.name
            && entry.version == p.version;
        let age = self.now_secs().checked_sub(entry.fetched_at)?;
        (entry.schema == CACHE_SCHEMA && same_key && age < self.ttl.as_secs())
            .then_some(entry.vulns)
    }

    /// Stores `vulns` for `p`. A failed write is ignored: the cache only saves a lookup.
    pub fn put(&self, p: &Package, vulns: &[Vuln]) {
        let entry = Entry {
            schema: CACHE_SCHEMA,
            ecosystem: p.ecosystem.osv_name().to_owned(),
            name: p.name.clone(),
            version: p.version.clone(),
            fetched_at: self.now_secs(),
            vulns: vulns.to_vec(),
        };
        let Ok(text) = serde_json::to_string(&entry) else {
            return;
        };
        let path = self.path(p);
        let tmp = path.with_extension("tmp");
        let written = fs::create_dir_all(&self.dir)
            .and_then(|()| fs::write(&tmp, text))
            .and_then(|()| fs::rename(&tmp, &path));
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
    }
}
