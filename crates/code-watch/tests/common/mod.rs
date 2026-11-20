//! Shared by the test binaries that write an executable and spawn processes in parallel threads.
#![allow(dead_code)]

use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};

/// Held while an executable is written or copied and while a child is spawned: a child forked by
/// another test thread keeps the write fd open until its exec, and exec of that file then fails
/// with ETXTBSY on Linux.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

pub fn spawn_lock() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `Command::output` with the spawn under the lock and the wait outside it.
pub fn output_of(cmd: &mut Command) -> Output {
    let child = {
        let _guard = spawn_lock();
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    child.wait_with_output().unwrap()
}
