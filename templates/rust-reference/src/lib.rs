#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OrderState {
    Pending {
        amount_cents: u32,
    },
    Authorized {
        amount_cents: u32,
        auth_code: String,
    },
    Shipped {
        amount_cents: u32,
        auth_code: String,
        tracking_id: String,
    },
    Cancelled {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OrderEvent {
    Authorize { auth_code: String },
    Ship { tracking_id: String },
    Cancel { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionCode {
    InvalidAuthCode,
    InvalidCancelReason,
    InvalidTrackingId,
    CannotShipUnpaid,
    AlreadyAuthorized,
    TerminalShipped,
    TerminalCancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionOutcome {
    Accepted(OrderState),
    Rejected {
        code: RejectionCode,
        unchanged: OrderState,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PricingError {
    InvalidDiscount(u8),
    Overflow,
}

#[must_use]
pub fn transition(state: OrderState, event: OrderEvent) -> TransitionOutcome {
    match state {
        OrderState::Pending { amount_cents } => match event {
            OrderEvent::Authorize { auth_code } => {
                if auth_code.trim().is_empty() {
                    TransitionOutcome::Rejected {
                        code: RejectionCode::InvalidAuthCode,
                        unchanged: OrderState::Pending { amount_cents },
                    }
                } else {
                    TransitionOutcome::Accepted(OrderState::Authorized {
                        amount_cents,
                        auth_code,
                    })
                }
            }
            OrderEvent::Cancel { reason } => {
                if reason.trim().is_empty() {
                    TransitionOutcome::Rejected {
                        code: RejectionCode::InvalidCancelReason,
                        unchanged: OrderState::Pending { amount_cents },
                    }
                } else {
                    TransitionOutcome::Accepted(OrderState::Cancelled { reason })
                }
            }
            OrderEvent::Ship { .. } => TransitionOutcome::Rejected {
                code: RejectionCode::CannotShipUnpaid,
                unchanged: OrderState::Pending { amount_cents },
            },
        },
        OrderState::Authorized {
            amount_cents,
            auth_code,
        } => match event {
            OrderEvent::Ship { tracking_id } => {
                if tracking_id.trim().is_empty() {
                    TransitionOutcome::Rejected {
                        code: RejectionCode::InvalidTrackingId,
                        unchanged: OrderState::Authorized {
                            amount_cents,
                            auth_code,
                        },
                    }
                } else {
                    TransitionOutcome::Accepted(OrderState::Shipped {
                        amount_cents,
                        auth_code,
                        tracking_id,
                    })
                }
            }
            OrderEvent::Cancel { reason } => {
                if reason.trim().is_empty() {
                    TransitionOutcome::Rejected {
                        code: RejectionCode::InvalidCancelReason,
                        unchanged: OrderState::Authorized {
                            amount_cents,
                            auth_code,
                        },
                    }
                } else {
                    TransitionOutcome::Accepted(OrderState::Cancelled { reason })
                }
            }
            OrderEvent::Authorize { .. } => TransitionOutcome::Rejected {
                code: RejectionCode::AlreadyAuthorized,
                unchanged: OrderState::Authorized {
                    amount_cents,
                    auth_code,
                },
            },
        },
        OrderState::Shipped {
            amount_cents,
            auth_code,
            tracking_id,
        } => TransitionOutcome::Rejected {
            code: RejectionCode::TerminalShipped,
            unchanged: OrderState::Shipped {
                amount_cents,
                auth_code,
                tracking_id,
            },
        },
        OrderState::Cancelled { reason } => TransitionOutcome::Rejected {
            code: RejectionCode::TerminalCancelled,
            unchanged: OrderState::Cancelled { reason },
        },
    }
}

#[must_use]
pub const fn state_name(state: &OrderState) -> &'static str {
    match state {
        OrderState::Pending { .. } => "pending",
        OrderState::Authorized { .. } => "authorized",
        OrderState::Shipped { .. } => "shipped",
        OrderState::Cancelled { .. } => "cancelled",
    }
}

pub fn calculate_total_cents(
    unit_price_cents: u32,
    quantity: u32,
    discount_percent: u8,
) -> Result<u32, PricingError> {
    if discount_percent > 100 {
        return Err(PricingError::InvalidDiscount(discount_percent));
    }
    let gross = u64::from(unit_price_cents)
        .checked_mul(u64::from(quantity))
        .ok_or(PricingError::Overflow)?;
    let discount = (gross * u64::from(discount_percent)) / 100;
    u32::try_from(gross - discount).map_err(|_| PricingError::Overflow)
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn verify_pricing_bounded_and_never_panics() {
        let unit_price: u32 = kani::any();
        let quantity: u32 = kani::any();
        let discount: u8 = kani::any();
        let result = calculate_total_cents(unit_price, quantity, discount);
        if discount > 100 {
            assert_eq!(result, Err(PricingError::InvalidDiscount(discount)));
        } else if let Ok(total) = result {
            let gross = u64::from(unit_price) * u64::from(quantity);
            assert!(u64::from(total) <= gross);
        }
    }

    #[kani::proof]
    fn verify_pending_cannot_ship_without_authorization() {
        let amount_cents: u32 = kani::any();
        let outcome = transition(
            OrderState::Pending { amount_cents },
            OrderEvent::Ship {
                tracking_id: String::from("TRK-1"),
            },
        );
        assert!(matches!(
            outcome,
            TransitionOutcome::Rejected {
                code: RejectionCode::CannotShipUnpaid,
                ..
            }
        ));
    }
}
