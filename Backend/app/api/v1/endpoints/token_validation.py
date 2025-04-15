"""
File for token-related endpoint functionality.
"""

# External imports
from fastapi import HTTPException, Header, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Optional, Callable
from functools import wraps

# Internal imports
from app.api.logger.logger import get_logger
from sqlalchemy.orm import Session
from app.api.v1.database.operations import DatabaseOperations


security = HTTPBearer()
logger = get_logger("app.api.endpoints.token_validation")


def validate_token(token: str, db: Session, get_id: bool = False):
    """Validates the token and optionally returns the user id"""
    logger.info("Validating token")
    user_id = DatabaseOperations(db).validate_token(token)
    if get_id:
        logger.info(
            f"Token validated, returning user id: {str(user_id)[:5]}..."
        )
        return user_id
    else:
        logger.info("Token validated")
        return True


def get_token(
    authorization: Optional[str] = Header(None),
    credentials: HTTPAuthorizationCredentials = Security(security),
):
    """Extracts the token in the request"""
    logger.info("Extracting token from header")
    if authorization is None:
        if credentials:
            return credentials.credentials
        raise HTTPException(
            status_code=401, detail="Authorization header missing"
        )
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return authorization


def requires_auth(get_id: bool = False):
    """
    A simple decorator that handles token validation inside the endpoint.

    Args:
        get_id: If True, the user_id will be returned and passed to the function.
    """

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            token = kwargs.get("token")
            db = kwargs.get("db")
            user_id = validate_token(token, db, get_id=True)
            kwargs.pop("token", None)
            if get_id:
                kwargs["user_id"] = user_id
            return await func(*args, **kwargs)

        return wrapper

    return decorator
