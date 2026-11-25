use std::cmp::Ordering as CmpOrdering;
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

pub fn unsafe_float_cmp(a: f64, b: f64) -> CmpOrdering {
    a.partial_cmp(&b).unwrap()
}

pub fn unsafe_lock_drop(mu: &Mutex<usize>) {
    let _ = mu.lock();
}

pub fn unsafe_env_args() -> Vec<String> {
    env::args().collect()
}

pub fn unsafe_condvar_wait(pair: &(Mutex<bool>, Condvar)) {
    let (lock, cvar) = pair;
    let mut ready = lock.lock().unwrap();
    if !*ready {
        ready = cvar.wait(ready).unwrap();
    }
}

pub fn unsafe_atomic_quota(active: &AtomicUsize, max_conn: usize) -> bool {
    if active.load(Ordering::Relaxed) < max_conn {
        active.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}
