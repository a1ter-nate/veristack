use order_lifecycle_ref::{OrderEvent, OrderState, TransitionOutcome, transition};
use stateright::{Checker, Model, Property};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TrackedOrder {
    state: OrderState,
    ever_authorized: bool,
    was_terminal: bool,
    terminal_mutated: bool,
    initial_amount: u32,
}

struct OrderLifecycleModel;

impl Model for OrderLifecycleModel {
    type State = TrackedOrder;
    type Action = OrderEvent;

    fn init_states(&self) -> Vec<Self::State> {
        vec![TrackedOrder {
            state: OrderState::Pending { amount_cents: 1500 },
            ever_authorized: false,
            was_terminal: false,
            terminal_mutated: false,
            initial_amount: 1500,
        }]
    }

    fn actions(&self, _state: &Self::State, actions: &mut Vec<Self::Action>) {
        actions.push(OrderEvent::Authorize {
            auth_code: String::from("AUTH-1"),
        });
        actions.push(OrderEvent::Authorize {
            auth_code: String::new(),
        });
        actions.push(OrderEvent::Ship {
            tracking_id: String::from("TRK-1"),
        });
        actions.push(OrderEvent::Ship {
            tracking_id: String::from(" "),
        });
        actions.push(OrderEvent::Cancel {
            reason: String::from("customer"),
        });
        actions.push(OrderEvent::Cancel {
            reason: String::new(),
        });
    }

    fn next_state(&self, last_state: &Self::State, action: Self::Action) -> Option<Self::State> {
        let next_order = match transition(last_state.state.clone(), action) {
            TransitionOutcome::Accepted(next) => next,
            TransitionOutcome::Rejected { unchanged, .. } => unchanged,
        };
        let now_authorized = matches!(next_order, OrderState::Authorized { .. });
        let now_terminal = matches!(
            next_order,
            OrderState::Shipped { .. } | OrderState::Cancelled { .. }
        );
        let mutated_after_terminal = last_state.was_terminal && next_order != last_state.state;

        Some(TrackedOrder {
            state: next_order,
            ever_authorized: last_state.ever_authorized || now_authorized,
            was_terminal: last_state.was_terminal || now_terminal,
            terminal_mutated: last_state.terminal_mutated || mutated_after_terminal,
            initial_amount: last_state.initial_amount,
        })
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always("no_unpaid_shipment", |_, s| match &s.state {
                OrderState::Shipped {
                    auth_code,
                    tracking_id,
                    ..
                } => {
                    s.ever_authorized
                        && !auth_code.trim().is_empty()
                        && !tracking_id.trim().is_empty()
                }
                OrderState::Pending { .. }
                | OrderState::Authorized { .. }
                | OrderState::Cancelled { .. } => true,
            }),
            Property::<Self>::always("terminal_states_are_immutable", |_, s| !s.terminal_mutated),
            Property::<Self>::always("amount_preserved_while_active", |_, s| match &s.state {
                OrderState::Pending { amount_cents }
                | OrderState::Authorized { amount_cents, .. }
                | OrderState::Shipped { amount_cents, .. } => *amount_cents == s.initial_amount,
                OrderState::Cancelled { reason } => !reason.trim().is_empty(),
            }),
            Property::<Self>::sometimes("can_reach_shipped", |_, s| {
                matches!(s.state, OrderState::Shipped { .. })
            }),
            Property::<Self>::sometimes("can_reach_cancelled", |_, s| {
                matches!(s.state, OrderState::Cancelled { .. })
            }),
        ]
    }
}

#[test]
fn exhaustive_stateright_model_check_proves_all_safety_and_reachability_invariants() {
    let checker = OrderLifecycleModel.checker().spawn_bfs().join();
    checker.assert_properties();
    assert!(checker.unique_state_count() >= 4);
}
