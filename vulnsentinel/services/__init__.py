"""Service layer — business logic orchestration."""


class ServiceError(Exception):
    """Base service exception."""


class NotFoundError(ServiceError):
    """Resource not found (-> HTTP 404)."""


class ConflictError(ServiceError):
    """Business rule conflict (-> HTTP 409)."""


class ValidationError(ServiceError):
    """Input validation or state transition error (-> HTTP 422)."""


class AuthenticationError(ServiceError):
    """Authentication failure (-> HTTP 401)."""
