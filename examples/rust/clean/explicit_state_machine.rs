pub enum PaymentState {
    Pending { amount_cents: u32 },
    Captured { amount_cents: u32, auth_code: String },
    Failed { reason: String },
}

pub fn describe_payment(state: &PaymentState) -> String {
    match state {
        PaymentState::Pending { amount_cents } => format!("Pending {amount_cents}"),
        PaymentState::Captured { auth_code, .. } => format!("Captured {auth_code}"),
        PaymentState::Failed { reason } => format!("Failed: {reason}"),
    }
}
