
from typing import Any, Dict, Optional
from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

class BaseAppException(Exception):
    def __init__(self, message: str, error_code: str = "INTERNAL_ERROR", status_code: int = 500, context: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.context = context or {}

    def to_dict(self) -> Dict[str, Any]:
        payload = {"error_code": self.error_code, "message": self.message, "status_code": self.status_code}
        if self.context:
            payload["context"] = self.context
        return payload

class InvariantViolationException(BaseAppException):
    def __init__(self, message: str, rule_name: str = "INVARIANT_VIOLATION", context: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, error_code=f"INVARIANT_{rule_name}", status_code=422, context=context)

class PolicyNotFoundException(BaseAppException):
    def __init__(self, policy_identifier: str, context: Optional[Dict[str, Any]] = None) -> None:
        ctx = context or {}
        ctx["policy_identifier"] = policy_identifier
        super().__init__(message=f"Risk policy '{policy_identifier}' does not exist.", error_code="POLICY_NOT_FOUND", status_code=404, context=ctx)

class AssessmentNotFoundException(BaseAppException):
    def __init__(self, assessment_id: str, context: Optional[Dict[str, Any]] = None) -> None:
        ctx = context or {}
        ctx["assessment_id"] = assessment_id
        super().__init__(message=f"Risk assessment '{assessment_id}' could not be found.", error_code="ASSESSMENT_NOT_FOUND", status_code=404, context=ctx)

class AuthenticationException(BaseAppException):
    def __init__(self, message: str = "Authentication required.", context: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message=message, error_code="AUTHENTICATION_FAILED", status_code=401, context=context)

class AuthorizationException(BaseAppException):
    def __init__(self, required_scope: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> None:
        ctx = context or {}
        if required_scope:
            ctx["required_scope"] = required_scope
        super().__init__(message="Forbidden: Insufficient privileges.", error_code="INSUFFICIENT_PERMISSIONS", status_code=403, context=ctx)

class IdempotencyConflictException(BaseAppException):
    def __init__(self, idempotency_key: str, context: Optional[Dict[str, Any]] = None) -> None:
        ctx = context or {}
        ctx["idempotency_key"] = idempotency_key
        super().__init__(message=f"Request with key '{idempotency_key}' is already processing.", error_code="IDEMPOTENCY_LOCKED", status_code=409, context=ctx)

async def app_exception_handler(_: Request, exc: BaseAppException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

async def value_error_handler(_: Request, exc: ValueError) -> JSONResponse:
    msg = str(exc)
    return JSONResponse(
        status_code=422,
        content={
            "error_code": "MODEL_VALIDATION_ERROR",
            "message": msg,
            "status_code": 422,
        },
    )

async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error_code": "REQUEST_VALIDATION_ERROR",
            "message": "Validation failed for request parameters or body.",
            "status_code": 422,
            # jsonable_encoder handles non-serializable ctx values such as the
            # raw ValueError embedded by pydantic in value_error details.
            "context": {"errors": jsonable_encoder(exc.errors())},
        },
    )

async def pydantic_validation_handler(_: Request, exc: ValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error_code": "MODEL_VALIDATION_ERROR",
            "message": "Data failed entity schema constraints.",
            "status_code": 422,
            "context": {"errors": jsonable_encoder(exc.errors())},
        },
    )

async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={
            "error_code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected server error occurred.",
            "status_code": 500,
            "context": {"detail": str(exc)},
        },
    )

def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(BaseAppException, app_exception_handler)
    app.add_exception_handler(ValueError, value_error_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValidationError, pydantic_validation_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
