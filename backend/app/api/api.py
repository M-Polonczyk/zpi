from fastapi import APIRouter

from app.core.config import settings

from .routes import login, pfsense, private, users, utils

api_router = APIRouter()
api_router.include_router(login.router)
api_router.include_router(users.router)
api_router.include_router(utils.router)
api_router.include_router(pfsense.router)


if settings.ENVIRONMENT == "local":
    api_router.include_router(private.router)
