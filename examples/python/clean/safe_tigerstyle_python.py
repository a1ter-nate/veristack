import asyncio
from decimal import Decimal

QUEUE_CAPACITY_MAX = 64


async def parse_amount(raw_amount: str) -> Decimal:
    if not raw_amount:
        raise ValueError("raw_amount must be non-empty")
    q: asyncio.Queue[str] = asyncio.Queue(maxsize=QUEUE_CAPACITY_MAX)
    return Decimal(raw_amount) + Decimal(q.qsize())
