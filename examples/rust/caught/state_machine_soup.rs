pub struct JobFlags {
    pub is_running: bool,
    pub is_stopped: bool,
    pub has_failed: bool,
}

pub struct PaymentBag {
    pub status: PaymentStatus,
    pub auth_code: Option<String>,
    pub failure_reason: Option<String>,
}

pub enum PaymentStatus {
    Pending,
    Captured,
    Failed,
}

pub fn describe_status(status: PaymentStatus) -> &'static str {
    match status {
        PaymentStatus::Pending => "waiting",
        _ => "other",
    }
}
