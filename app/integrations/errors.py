class IntegrationError(Exception):
    """A safe error message which never includes provider responses or credentials."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "integration_unavailable",
        status_code: int = 503,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
