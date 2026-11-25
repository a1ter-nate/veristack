import Base

type Order is Data:
  Pending{id: U32}
  Cancelled{id: U32}
  Shipped{id: U32}

type OrderStatus is Data:
  StPending{}
  StCancelled{}
  StShipped{}

def cancel(order: Order) -> Order:
  match order:
    case Pending{id}:
      Cancelled{id}
    case Cancelled{id}:
      Cancelled{id}
    case Shipped{id}:
      Shipped{id}

def sat_sub(a: Nat, b: Nat) -> Nat:
  match a:
    case 0n:
      0n
    case 1n+pa:
      match b:
        case 0n:
          1n+pa
        case 1n+pb:
          sat_sub(pa, pb)

def clamp_nat(cap: Nat, x: Nat) -> Nat:
  match cap:
    case 0n:
      0n
    case 1n+pc:
      match x:
        case 0n:
          0n
        case 1n+px:
          1n+clamp_nat(pc, px)

def encode_status(s: OrderStatus) -> Nat:
  match s:
    case StPending{}:
      0n
    case StCancelled{}:
      1n
    case StShipped{}:
      2n

def decode_status(code: Nat) -> OrderStatus:
  match code:
    case 0n:
      StPending{}
    case 1n+p1:
      match p1:
        case 0n:
          StCancelled{}
        case 1n+_:
          StShipped{}

def unwind_all(xs: List<U32>) -> List<U32>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{_, tail}:
      unwind_all(tail)
