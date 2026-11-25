import Base
import ./Model.bend as Model

law cancel_idempotent:
  for order: Model.Order
  {Model.cancel(Model.cancel(order)) == Model.cancel(order) : Model.Order}

law shipped_never_cancelled:
  for id: U32
  {Model.cancel(Model.Shipped{id}) == Model.Shipped{id} : Model.Order}

law sat_sub_zero_left:
  for b: Nat
  {Model.sat_sub(0n, b) == 0n : Nat}

law clamp_respects_zero_cap:
  for x: Nat
  {Model.clamp_nat(0n, x) == 0n : Nat}

law status_roundtrip:
  for s: Model.OrderStatus
  {Model.decode_status(Model.encode_status(s)) == s : Model.OrderStatus}

law unwind_restores_empty:
  for xs: List<U32>
  {Model.unwind_all(xs) == Nil{} : List<U32>}
