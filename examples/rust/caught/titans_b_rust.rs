use std::cell::RefCell;
use std::ffi::OsStr;

pub struct WorkerGuard {
    pub id: u64,
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        let _ = tokio::spawn(async move {});
    }
}

pub fn unsafe_path_to_str(path: &OsStr) -> &str {
    path.to_str().unwrap()
}

pub fn notify_under_borrow<F: Fn(usize)>(state: &RefCell<Vec<usize>>, callback: F) {
    let guard = state.borrow_mut();
    callback(guard.len());
}
