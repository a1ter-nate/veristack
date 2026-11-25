package orderlifecycle

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"testing/quick"
)

type transitionRow struct {
	From  Status `json:"from"`
	Event Event  `json:"event"`
	OK    bool   `json:"ok"`
	To    Status `json:"to"`
}

func TestTransitionTable(t *testing.T) {
	raw, err := os.ReadFile("transition-table.json")
	if err != nil {
		t.Fatalf("read transition-table.json: %v", err)
	}
	var rows []transitionRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("unmarshal transition-table.json: %v", err)
	}
	for _, row := range rows {
		start := Order{ID: "ord-1", AmountCent: 1000, Status: row.From}
		next, err := Transition(start, row.Event)
		if row.OK && err != nil {
			t.Errorf("%s +%s: unexpected err %v", row.From, row.Event, err)
		}
		if !row.OK && !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("%s +%s: expected ErrInvalidTransition, got %v", row.From, row.Event, err)
		}
		if next.Status != row.To {
			t.Errorf("%s +%s: expected status %s, got %s", row.From, row.Event, row.To, next.Status)
		}
	}
}

func TestApplyDiscountPropertyBounds(t *testing.T) {
	prop := func(amount uint32, pct uint8) bool {
		res, err := ApplyDiscount(uint64(amount), pct)
		if pct > 100 {
			return errors.Is(err, ErrInvalidDiscount)
		}
		return err == nil && res <= uint64(amount)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("discount property failed: %v", err)
	}
}

func TestOrderStatefulModelBasedInvariants(t *testing.T) {
	events := []Event{EventPay, EventShip, EventCancel}
	prop := func(ops []uint8) bool {
		order := NewOrder("mbt-1", 2500)
		wasShipped := false
		for _, op := range ops {
			ev := events[int(op)%len(events)]
			next, err := Transition(order, ev)
			if err == nil {
				order = next
			}
			if order.Status == StatusShipped {
				wasShipped = true
			}
			if wasShipped && order.Status != StatusShipped {
				return false
			}
			if order.Status == StatusCancelled {
				again, againErr := Transition(order, EventCancel)
				if againErr != nil || again.Status != StatusCancelled {
					return false
				}
			}
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 300}); err != nil {
		t.Fatalf("stateful MBT invariant violated: %v", err)
	}
}
