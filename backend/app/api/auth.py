from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.config import settings
from app.core.security import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, verify_password

router = APIRouter()


@router.post("/token", summary="Create an analyst access token")
async def create_token(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    if (
        not settings.ADMIN_PASSWORD_HASH
        or form_data.username != settings.ADMIN_USERNAME
        or not verify_password(form_data.password, settings.ADMIN_PASSWORD_HASH)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        {"sub": settings.ADMIN_USERNAME},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    response.set_cookie(
        "rajawali_session",
        token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=settings.ENV.lower() == "production",
        samesite="strict",
    )
    return {"access_token": token, "token_type": "bearer"}
