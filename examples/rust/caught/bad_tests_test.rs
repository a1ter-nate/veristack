use crate::state_machine_soup::{describe_status, PaymentStatus};
use std::env;
use std::thread;
use std::time::{Duration, SystemTime};

#[ignore]
#[test]
fn ignored_tautology() {
    assert!(true);
}

#[test]
fn flaky_non_hermetic() {
    env::set_var("MODE", "test");
    let _now = SystemTime::now();
    thread::sleep(Duration::from_millis(25));
    assert_eq!(describe_status(PaymentStatus::Pending), "waiting");
}
