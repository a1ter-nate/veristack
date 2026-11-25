import Base
import ./Model.bend as Model
import ./LAWS.bend as LAWS

def LAWS.cancel_idempotent(order):
  match order:
    case Model.Pending{id}:
      {==}
    case Model.Cancelled{id}:
      {==}
    case Model.Shipped{id}:
      {==}

def LAWS.shipped_never_cancelled(id):
  {==}

def LAWS.sat_sub_zero_left(b):
  {==}

def LAWS.clamp_respects_zero_cap(x):
  {==}

def LAWS.status_roundtrip(s):
  match s:
    case Model.StPending{}:
      {==}
    case Model.StCancelled{}:
      {==}
    case Model.StShipped{}:
      {==}

def LAWS.unwind_restores_empty(xs):
  match xs:
    case Nil{}:
      {==}
    case Con{_, tail}:
      LAWS.unwind_restores_empty(tail)
