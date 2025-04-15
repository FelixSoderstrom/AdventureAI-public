"""
The game loop, Everything gathered here from user input to image generation.
"""

# External imports
from typing import Dict

# Internal imports
from app.api.v1.game.context_manager import GameContextManager
from app.api.v1.validation.schemas import StoryActionSegment, GameSession
from app.api.logger.loggable import Loggable


class SceneGenerator(Loggable):
    def __init__(self, db=None):
        super().__init__()
        self.manager = GameContextManager()
        self.logger.info("SceneGenerator initialized")

    async def get_dice_info(self, story: StoryActionSegment):
        """Rolls the dice and returns the result"""
        self.logger.info(f"Rolling dice for action: {story.action}")
        return await self.manager.roll_dice(story)

    async def get_next_scene(self, game_session: GameSession):
        """
        Takes context as input and sends new context as output
        """
        self.logger.info(
            f"Generating the {len(game_session.scenes) + 1}th scene."
        )
        story: str = await self.manager.new_story(game_session)
        compressed_story: str = await self.manager.compress(story)
        image: str = await self.manager.generate_image(story)
        music_path: str = await self.manager.analyze_mood(story)
        return {
            "story": story,
            "compressed_story": compressed_story,
            "image": image,
            "music": music_path,
        }

    async def save_game(self, game_session: Dict):
        """Saves the game to the database"""
        self.logger.info(
            f"Saving game state for session: {game_session.get('id', 'unknown')}"
        )
        pass
