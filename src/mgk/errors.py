"""Closed error taxonomy used by the authority boundary."""


class MGKError(Exception):
    code = "MGK_ERROR"


class CanonicalizationError(MGKError, ValueError):
    code = "CANONICALIZATION_ERROR"


class SchemaError(MGKError):
    code = "SCHEMA_ERROR"


class AuthorizationDenied(MGKError):
    code = "AUTHORIZATION_DENIED"


class SignatureError(MGKError):
    code = "SIGNATURE_ERROR"


class EpochError(MGKError):
    code = "EPOCH_ERROR"


class TimeWindowError(MGKError):
    code = "TIME_WINDOW_ERROR"


class ReplayError(MGKError):
    code = "REPLAY_ERROR"


class ScopeError(MGKError):
    code = "SCOPE_ERROR"


class ResourceError(MGKError):
    code = "RESOURCE_ERROR"


class StateIntegrityError(MGKError):
    code = "STATE_INTEGRITY_ERROR"


class AuditIntegrityError(MGKError):
    code = "AUDIT_INTEGRITY_ERROR"


class ExecutionDenied(MGKError):
    code = "EXECUTION_DENIED"
