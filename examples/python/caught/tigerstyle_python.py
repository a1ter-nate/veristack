import asyncio


@retry()
def sync_price(raw_amount: str) -> float:
    amount_usd = float(raw_amount)
    q = asyncio.Queue()
    return amount_usd + q.qsize()
