"""Business logic. Web and API layers call these functions; they never touch the DB directly for writes."""


class ServiceError(Exception):
    """A business rule was violated (shown to the user, HTTP 400/409)."""

    status_code = 400

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        if status_code:
            self.status_code = status_code


class PermissionDenied(ServiceError):
    status_code = 403


class NotFound(ServiceError):
    status_code = 404
