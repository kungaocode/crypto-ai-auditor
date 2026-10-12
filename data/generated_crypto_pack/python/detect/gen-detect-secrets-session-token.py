import secrets


class SessionManager:
    def new_session_id(self) -> str:
        return secrets.token_urlsafe(32)

    def new_csrf_token(self) -> str:
        return secrets.token_urlsafe(24)
