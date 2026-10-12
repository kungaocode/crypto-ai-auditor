import random


def create_reset_token() -> str:
    token = random.getrandbits(128)
    return f"{token:032x}"
