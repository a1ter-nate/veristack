type Order is Data:
  Pending{id: U32}
  Cancelled{id: U32}
  Shipped{id: U32}

def cancel(order: Order) -> Order:
  match order:
    case Pending{id}:
      Cancelled{id}
    case Cancelled{id}:
      Cancelled{id}
    case Shipped{id}:
      Shipped{id}

law cancel_idempotent(order: Order):
  {cancel(cancel(order)) == cancel(order) : Order}

def cancel_idempotent(order: Order) -> {cancel(cancel(order)) == cancel(order) : Order}:
  match order:
    case Pending{id}:
      {==}
    case Cancelled{id}:
      {==}
    case Shipped{id}:
      {==}

law shipped_never_cancelled(id: U32):
  {cancel(Shipped{id}) == Shipped{id} : Order}

def shipped_never_cancelled(id: U32) -> {cancel(Shipped{id}) == Shipped{id} : Order}:
  {==}
