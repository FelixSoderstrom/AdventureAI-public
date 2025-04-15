"""
File that constructs all prompts being used for LLM requests.
"""

# External imports
from typing import Dict, List

# Internal imports
from app.api.v1.game.instructions import instructions
from app.api.v1.validation.schemas import StoryActionSegment, GameSession
from app.api.logger.loggable import Loggable


class PromptBuilder(Loggable):
    """Class that handles all prompt building before a LLM-call"""

    def __init__(self):
        super().__init__()
        self.instructions = instructions
        self.logger.info("PromptBuilder initialized")

    async def get_dice_prompt(self, recent_scene: StoryActionSegment):
        """Builds the prompt for the dice roll"""
        self.logger.info(
            f"Building dice prompt for action: {recent_scene.action}"
        )
        instructions = self.instructions["determine_dice_roll"]
        story = recent_scene.story
        action = recent_scene.action
        prompt = (
            f"Instructions: {instructions}\n\n"
            f"Story: {story}\n"
            f"Action: {action}\n"
        )
        self.logger.debug(f"Dice prompt built (prompt length: {len(prompt)})")
        return prompt

    def get_story_prompt(self, game_session: GameSession) -> str:
        """Builds the prompt for new stories"""
        self.logger.info("Building story prompt")
        instructions: str = self.instructions["generate_story"]
        name: str = game_session.protagonist_name
        inv: str = ", ".join(game_session.inventory)
        recent_scenes: List[Dict] = game_session.scenes[-10:]
        action: str = recent_scenes[-1]["action"]
        success: bool = recent_scenes[-1]["dice_success"]
        prompt = (
            f"Instructions: {instructions}\n\n"
            f"Protagonist name: {name}\n"
            f"Protagonist's inventory: {inv}\n\n"
            "The story so far:\n"
        )
        for i, scene in enumerate(recent_scenes, 1):
            prompt += f"Story {i}: {scene['story']}\n\n"
        prompt += f"Protagonist's action based on the last story: {action}\n"
        prompt += f"Action successful: {success}\n\n"
        prompt += f"Story {len(recent_scenes) + 1}: Please write this story based on what just happened.\n\n"
        self.logger.debug(f"Story prompt built with length: {len(prompt)})")
        return prompt

    async def get_compress_prompt(self, story: str):
        """Builds the prompt for compressing a story"""
        self.logger.info(
            f"Building compression prompt for story with length: {len(story)})"
        )
        instructions = self.instructions["compress_story"]
        prompt = f"Instructions: {instructions}\n" f"Story: {story}"
        self.logger.debug(
            f"Compression prompt built with length: {len(prompt)})"
        )
        return prompt

    async def get_img_prompt(self, story: str):
        """Build the prompt for image generation"""
        self.logger.info(
            f"Building image prompt for story with length: {len(story)})"
        )
        instructions = self.instructions["image_prompt"]
        prompt = f"""
            Instructions: {instructions}

            Story: {story}
        """
        self.logger.debug(f"Image prompt built with length: {len(prompt)})")
        return prompt

    async def get_mood_prompt(self, story: str):
        """Build the prompt for mood analysis"""
        self.logger.info(
            f"Building mood analysis prompt for story with length: {len(story)})"
        )
        instructions = self.instructions["analyze_mood"]
        prompt = f"Instructions: {instructions}\nStory: {story}"
        return prompt
