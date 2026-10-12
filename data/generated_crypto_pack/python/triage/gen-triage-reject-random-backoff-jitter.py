import random


def retry_delay(attempt: int) -> float:
    jitter = random.uniform(0.0, 0.25)
    return min(30.0, 0.5 * (2**attempt)) + jitter
