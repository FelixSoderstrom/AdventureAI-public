# External imports
from fastapi import APIRouter

# Internal imports
from app.api.v1.endpoints import game_endpoints, user_endpoints

router = APIRouter(prefix="/v1")
router.include_router(game_endpoints.router)
router.include_router(user_endpoints.router)
