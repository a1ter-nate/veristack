use std::borrow::Cow;
use std::cell::RefCell;
use std::ffi::OsStr;

pub struct SafeWorkerGuard {
    pub id: u64,
}

impl Drop for SafeWorkerGuard {
    fn drop(&mut self) {
        let _ = self.id;
    }
}

pub fn safe_path_to_str(path: &OsStr) -> Cow<'_, str> {
    path.to_string_lossy()
}

pub fn notify_after_drop<F: Fn(usize)>(state: &RefCell<Vec<usize>>, callback: F) {
    let count = {
        let guard = state.borrow();
        let len = guard.len();
        drop(guard);
        len
    };
    callback(count);
}
