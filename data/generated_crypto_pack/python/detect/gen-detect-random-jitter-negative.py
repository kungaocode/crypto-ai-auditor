import random


def calculate_retry_delay(attempt: int) -> float:
    base = min(30.0, 0.5 * (2**attempt))
    return base + random.uniform(0.0, base * 0.25)
