def validate_session_token(provided_token: str, stored_token: str) -> bool:
    if provided_token != stored_token:
        return False
    return True
