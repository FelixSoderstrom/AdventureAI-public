# External imports
from fastapi import APIRouter, Depends, Request
from typing import Dict, List
from sqlalchemy.orm import Session
from uuid import UUID

# Internal imports
from app.db_setup import get_db
from app.api.logger.logger import get_logger
from app.api.v1.game.game_loop import SceneGenerator
from app.api.v1.database.operations import DatabaseOperations
from app.api.v1.endpoints.token_validation import get_token, requires_auth
from app.api.v1.endpoints.rate_limiting import rate_limit
from app.api.v1.validation.schemas import (
    StartingStory,
    StoryActionSegment,
    GameSession,
    SaveGame,
)

logger = get_logger("app.api.endpoints.game")
router = APIRouter(tags=["game"])


@router.post("/")
@requires_auth(get_id=True)
@rate_limit(authenticated_limit=0, unauthenticated_limit=0)
async def function1(
    request: Request,
    story: StartingStory,
    db: Session = Depends(get_db),
    token: str = Depends(get_token),
    user_id: UUID = None,
):
    """Fetches a starting story from the database."""
    logger.info(f"User ID: {str(user_id)[:5]}... " "was granted access to /")
    response = DatabaseOperations(db).get_start_story(story.story_id)
    logger.info("Returning starting story to client")
    return response


@router.post("/")
@requires_auth(get_id=True)
@rate_limit(authenticated_limit=0, unauthenticated_limit=0)
async def function2(
    request: Request,
    story: StoryActionSegment,
    db: Session = Depends(get_db),
    token: str = Depends(get_token),
    user_id: UUID = None,
) -> Dict[str, str | int | bool]:
    """Rolls dice on a story/action segment"""
    logger.info(f"User ID: {str(user_id)[:5]}... " "was granted access to /")
    dice_info = await SceneGenerator(db).get_dice_info(story)
    logger.info(f"Dice rolled: {dice_info}")
    return dice_info


@router.post("/")
@requires_auth(get_id=True)
@rate_limit(authenticated_limit=0, unauthenticated_limit=0)
async def function3(
    request: Request,
    game_session: GameSession,
    db: Session = Depends(get_db),
    token: str = Depends(get_token),
    user_id: UUID = None,
) -> Dict[str, str]:
    """Generates a new scene based on the previous one."""
    logger.info(f"User ID: {str(user_id)[:5]}... " "was granted access to /")
    scene = await SceneGenerator(db).get_next_scene(game_session)
    logger.info("Successfully generated new scene.")
    return scene


@router.post("/")
@requires_auth(get_id=True)
@rate_limit(authenticated_limit=0, unauthenticated_limit=0)
async def function4(
    request: Request,
    game: SaveGame,
    db: Session = Depends(get_db),
    token: str = Depends(get_token),
    user_id: int = None,
) -> Dict[str, int]:
    """Saves stories and user input to the database."""
    logger.info(f"User ID: {str(user_id)[:5]}... was granted access to /")
    game_id = DatabaseOperations(db).save_game_route(game, user_id)
    return {"game_id": game_id}


@router.get("/")
@requires_auth(get_id=True)
@rate_limit(authenticated_limit=0, unauthenticated_limit=0)
async def function5(
    request: Request,
    db: Session = Depends(get_db),
    token: str = Depends(get_token),
    user_id: int = None,
):
    """Loads a game session from the database."""
    logger.info(f"User ID: {str(user_id)[:5]}... was granted access to /")
    saves: List[GameSession] = DatabaseOperations(db).load_game(user_id)
    logger.info("Returning saves to client")
    return {"saves": saves}
