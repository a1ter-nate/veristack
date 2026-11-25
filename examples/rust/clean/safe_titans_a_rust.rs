use std::cmp::Ordering as CmpOrdering;
use std::env;
use std::ffi::OsString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

pub fn safe_float_cmp(a: f64, b: f64) -> CmpOrdering {
    a.total_cmp(&b)
}

pub fn safe_lock_guard(mu: &Mutex<usize>) -> Option<usize> {
    let _guard = mu.lock().ok()?;
    Some(*_guard)
}

pub fn safe_env_args() -> Vec<OsString> {
    env::args_os().collect()
}

pub fn safe_condvar_wait(pair: &(Mutex<bool>, Condvar)) -> bool {
    let (lock, cvar) = pair;
    if let Ok(guard) = lock.lock() {
        return cvar.wait_while(guard, |ready| !*ready).is_ok();
    }
    false
}

pub fn safe_atomic_quota(active: &AtomicUsize, max_conn: usize) -> bool {
    let mut current = active.load(Ordering::Acquire);
    while current < max_conn {
        match active.compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
    false
}
