use order_lifecycle_ref::{
    OrderEvent, OrderState, PricingError, TransitionOutcome, calculate_total_cents, state_name,
    transition,
};
use proptest::prelude::*;

fn event_strategy() -> impl Strategy<Value = OrderEvent> {
    prop_oneof![
        Just(OrderEvent::Authorize {
            auth_code: String::from("AUTH-OK"),
        }),
        Just(OrderEvent::Authorize {
            auth_code: String::new(),
        }),
        Just(OrderEvent::Ship {
            tracking_id: String::from("TRK-OK"),
        }),
        Just(OrderEvent::Ship {
            tracking_id: String::from(" "),
        }),
        Just(OrderEvent::Cancel {
            reason: String::from("customer"),
        }),
        Just(OrderEvent::Cancel {
            reason: String::new(),
        }),
    ]
}

fn reference_next(phase: &'static str, event: &OrderEvent) -> &'static str {
    match (phase, event) {
        ("pending", OrderEvent::Authorize { auth_code }) if !auth_code.trim().is_empty() => {
            "authorized"
        }
        ("pending" | "authorized", OrderEvent::Cancel { reason }) if !reason.trim().is_empty() => {
            "cancelled"
        }
        ("authorized", OrderEvent::Ship { tracking_id }) if !tracking_id.trim().is_empty() => {
            "shipped"
        }
        _ => phase,
    }
}

proptest! {
    #[test]
    fn pricing_is_bounded_and_exact_at_extremes(
        unit_price in 0u32..10_000,
        qty in 0u32..500,
        discount in 0u8..=100,
    ) {
        let total = calculate_total_cents(unit_price, qty, discount);
        let gross = unit_price * qty;
        prop_assert!(total.is_ok());
        if let Ok(value) = total {
            prop_assert!(value <= gross);
        }
        prop_assert_eq!(calculate_total_cents(unit_price, qty, 0), Ok(gross));
        prop_assert_eq!(calculate_total_cents(unit_price, qty, 100), Ok(0));
    }

    #[test]
    fn stateful_mbt_holds_across_arbitrary_event_sequences(
        events in prop::collection::vec(event_strategy(), 1..40),
    ) {
        let mut sut = OrderState::Pending { amount_cents: 2500 };
        let mut model_phase = "pending";

        for event in events {
            model_phase = reference_next(model_phase, &event);
            sut = match transition(sut, event) {
                TransitionOutcome::Accepted(next) => next,
                TransitionOutcome::Rejected { unchanged, .. } => unchanged,
            };
            prop_assert_eq!(state_name(&sut), model_phase);
        }
    }
}

#[test]
fn pricing_rejects_discount_above_100_and_overflow() {
    assert_eq!(
        calculate_total_cents(100, 1, 101),
        Err(PricingError::InvalidDiscount(101))
    );
    assert_eq!(
        calculate_total_cents(u32::MAX, 2, 0),
        Err(PricingError::Overflow)
    );
}
