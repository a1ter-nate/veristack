package orderlifecycle

import (
	"errors"
	"math"
)

type Status string

const (
	StatusPending   Status = "pending"
	StatusPaid      Status = "paid"
	StatusShipped   Status = "shipped"
	StatusCancelled Status = "cancelled"
)

type Event string

const (
	EventPay    Event = "pay"
	EventShip   Event = "ship"
	EventCancel Event = "cancel"
)

var (
	ErrInvalidTransition = errors.New("invalid state transition")
	ErrInvalidDiscount   = errors.New("discount percent must be between 0 and 100")
	ErrOverflow          = errors.New("integer arithmetic overflow")
)

type Order struct {
	ID         string
	AmountCent uint64
	Status     Status
}

func NewOrder(id string, amountCent uint64) Order {
	return Order{ID: id, AmountCent: amountCent, Status: StatusPending}
}

func Transition(order Order, event Event) (Order, error) {
	switch order.Status {
	case StatusPending:
		switch event {
		case EventPay:
			order.Status = StatusPaid
			return order, nil
		case EventCancel:
			order.Status = StatusCancelled
			return order, nil
		case EventShip:
			return order, ErrInvalidTransition
		}
	case StatusPaid:
		switch event {
		case EventShip:
			order.Status = StatusShipped
			return order, nil
		case EventCancel:
			order.Status = StatusCancelled
			return order, nil
		case EventPay:
			return order, ErrInvalidTransition
		}
	case StatusShipped:
		return order, ErrInvalidTransition
	case StatusCancelled:
		if event == EventCancel {
			return order, nil
		}
		return order, ErrInvalidTransition
	}
	return order, ErrInvalidTransition
}

func ApplyDiscount(amountCent uint64, percent uint8) (uint64, error) {
	if percent > 100 {
		return 0, ErrInvalidDiscount
	}
	if amountCent > math.MaxUint64/100 {
		return 0, ErrOverflow
	}
	discount := (amountCent * uint64(percent)) / 100
	return amountCent - discount, nil
}
