use order_lifecycle_ref::{
    OrderEvent, OrderState, RejectionCode, TransitionOutcome, state_name, transition,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct TransitionRow {
    name: String,
    initial: String,
    event: String,
    arg: String,
    accepted: bool,
    expected: String,
    error_code: String,
}

fn build_state(kind: &str) -> Result<OrderState, String> {
    match kind {
        "pending" => Ok(OrderState::Pending { amount_cents: 1500 }),
        "authorized" => Ok(OrderState::Authorized {
            amount_cents: 1500,
            auth_code: String::from("AUTH-0"),
        }),
        "shipped" => Ok(OrderState::Shipped {
            amount_cents: 1500,
            auth_code: String::from("AUTH-0"),
            tracking_id: String::from("TRK-0"),
        }),
        "cancelled" => Ok(OrderState::Cancelled {
            reason: String::from("init"),
        }),
        other => Err(format!("unknown state fixture: {other}")),
    }
}

fn build_event(kind: &str, arg: String) -> Result<OrderEvent, String> {
    match kind {
        "authorize" => Ok(OrderEvent::Authorize { auth_code: arg }),
        "ship" => Ok(OrderEvent::Ship { tracking_id: arg }),
        "cancel" => Ok(OrderEvent::Cancel { reason: arg }),
        other => Err(format!("unknown event fixture: {other}")),
    }
}

const fn code_name(code: &RejectionCode) -> &'static str {
    match code {
        RejectionCode::InvalidAuthCode => "INVALID_AUTH_CODE",
        RejectionCode::InvalidCancelReason => "INVALID_CANCEL_REASON",
        RejectionCode::InvalidTrackingId => "INVALID_TRACKING_ID",
        RejectionCode::CannotShipUnpaid => "CANNOT_SHIP_UNPAID",
        RejectionCode::AlreadyAuthorized => "ALREADY_AUTHORIZED",
        RejectionCode::TerminalShipped => "TERMINAL_SHIPPED",
        RejectionCode::TerminalCancelled => "TERMINAL_CANCELLED",
    }
}

#[test]
fn transition_matrix_matches_tests_as_data_json() -> Result<(), String> {
    let raw = include_str!("fixtures/transitions.json");
    let rows: Vec<TransitionRow> = serde_json::from_str(raw).map_err(|e| e.to_string())?;

    for row in rows {
        let initial = build_state(&row.initial)?;
        let event = build_event(&row.event, row.arg)?;
        let outcome = transition(initial.clone(), event);

        if row.accepted {
            match outcome {
                TransitionOutcome::Accepted(next) => {
                    assert_eq!(state_name(&next), row.expected, "row: {}", row.name);
                }
                TransitionOutcome::Rejected { code, .. } => {
                    return Err(format!(
                        "row {} expected Accepted, got Rejected({code:?})",
                        row.name
                    ));
                }
            }
        } else {
            match outcome {
                TransitionOutcome::Rejected { code, unchanged } => {
                    assert_eq!(code_name(&code), row.error_code, "row: {}", row.name);
                    assert_eq!(state_name(&unchanged), row.expected, "row: {}", row.name);
                    assert_eq!(unchanged, initial, "row: {}", row.name);
                }
                TransitionOutcome::Accepted(next) => {
                    return Err(format!(
                        "row {} expected Rejected, got Accepted({next:?})",
                        row.name
                    ));
                }
            }
        }
    }

    Ok(())
}
