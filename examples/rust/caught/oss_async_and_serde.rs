use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BadConfig {
    pub name: String,
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

pub fn deadline_unchecked(d: Duration) -> Instant {
    Instant::now() + d
}

pub fn poll(_cx: &mut Context<'_>) -> Poll<()> {
    Poll::Pending
}

pub fn drop_under_lock(m: &Mutex<Option<String>>, handle: String) {
    let guard = m.lock();
    drop(handle);
    drop(guard);
}

pub fn run_cmd(mut cmd: Command, env_hash_map: HashMap<String, String>) -> Command {
    cmd.envs(&env_hash_map);
    cmd
}

pub async fn cancel_unsafe_select() {
    tokio::select! {
        _ = reader.read_exact(&mut buf) => {}
    }
}
