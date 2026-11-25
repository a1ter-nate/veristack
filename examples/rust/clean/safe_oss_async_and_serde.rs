use std::collections::BTreeMap;
use std::process::Command;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

pub struct SafeConfig {
    pub name: String,
    pub extra: BTreeMap<String, String>,
}

pub fn deadline_checked(d: Duration) -> Option<Instant> {
    Instant::now().checked_add(d)
}

pub fn poll_registered(cx: &mut Context<'_>) -> Poll<()> {
    cx.waker().wake_by_ref();
    Poll::Pending
}

pub fn run_cmd_deterministic(mut cmd: Command, env_map: BTreeMap<String, String>) -> Command {
    cmd.envs(&env_map);
    cmd
}
