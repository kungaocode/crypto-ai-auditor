import random


def create_reset_token() -> str:
    reset_token = random.getrandbits(128)
    return f"{reset_token:032x}"
