"""
File that handles the context (game session)
Makes API calls, build prompt.
Sort of a middleman between game loop and generative apis.
"""

# External imports
from typing import Dict
from random import randint
from re import sub
from difflib import get_close_matches

# Internal imports
from app.api.v1.game.prompt_builder import PromptBuilder
from app.api.v1.validation.schemas import StoryActionSegment, GameSession
from app.api.logger.loggable import Loggable
from app.api.v1.game.generative_apis import (
    TextGeneration,
    ImageGeneration,
    SoundGeneration,
)


class GameContextManager(Loggable):
    def __init__(self):
        super().__init__()
        self.text = TextGeneration()
        self.image = ImageGeneration()
        self.sound = SoundGeneration()
        self.prompt = PromptBuilder()
        self.previous_stories = []
        self.logger.info("GameContextManager initialized")

    async def roll_dice(self, recent_scene: StoryActionSegment) -> Dict:
        """Calls LLM to determine dice threshold and rolls dice"""
        self.logger.info(f"Rolling dice for action: {recent_scene.action}")
        prompt = await self.prompt.get_dice_prompt(recent_scene)
        llm_output = await self.text.api_call(prompt)
        threshold: int = await self._convert_dice_threshold_to_int(llm_output)
        roll: int = randint(1, 20)
        success: bool = roll >= threshold
        dice_results = {
            "dice_threshold": threshold,
            "dice_roll": roll,
            "dice_success": success,
        }
        return dice_results

    async def _convert_dice_threshold_to_int(self, llm_output: str) -> int:
        """Converts LLM output for dice threshold to integer"""
        self.logger.debug(f"Converting LLM output to integer: '{llm_output}'")
        threshold = sub(r"[^0-9]", "", str(llm_output))
        if threshold == "":
            return 0  # Give the user an out
        threshold = int(threshold)
        if threshold > 20:
            threshold = 20
        return threshold

    async def new_story(self, game_session: GameSession) -> Dict:
        """Gets prompt and makes API call"""
        prompt = self.prompt.get_story_prompt(game_session)
        new_story = await self.text.api_call(prompt)
        self.logger.info(f"New story generated (length: {len(new_story)})")
        return new_story

    async def compress(self, story: str) -> str:
        """Uses LLM API to shorten the story"""
        self.logger.info(f"Compressing story (original length: {len(story)})")
        prompt = await self.prompt.get_compress_prompt(story)
        compressed_story = await self.text.api_call(prompt)
        self.logger.info(
            f"Story compressed (new length: {len(compressed_story)})"
        )

        return compressed_story

    async def generate_image(self, story: str) -> str:
        """Builds prompt and returns image"""
        self.logger.info("Generating image for story")
        prompt_for_llm = await self.prompt.get_img_prompt(story)
        prompt_for_sd = await self.text.api_call(prompt_for_llm)
        self.logger.debug(
            f"Stable diffusion prompt(non-spicy) received: {prompt_for_sd}"
        )
        spicy_prompt = (
            "highly detailed, masterpiece, 8k, photorealistic, "
            "sharp focus, volumetric lighting, professional color grading, "
            "cinematic lighting, perfect composition, " + prompt_for_sd
        )
        self.logger.debug("Sending request to image generation API")
        image: str = await self.image.api_call(spicy_prompt)
        self.logger.info("Image successfully generated")

        return image

    async def analyze_mood(self, story: str) -> str:
        """Analyzes the mood of the story and returns path to appropriate music"""
        self.logger.info("Analyzing mood of story for music selection")
        prompt = await self.prompt.get_mood_prompt(story)
        llm_output = await self.text.api_call(prompt)
        self.logger.debug(f"Mood analysis LLM output: {llm_output}")
        music_path = self._validate_mood_prompt(llm_output)
        self.logger.info(f"Music path after validation: {music_path}")
        return music_path

    def _validate_mood_prompt(self, prompt: str) -> str:
        """Validates the mood prompt"""
        self.logger.debug(f"Validating mood prompt: {prompt[:100]}...")
        valid_combinations = {
            "calm": ["adventerous", "dreamy", "mystical", "serene"],
            "medium": [
                "lurking",
                "nervous",
                "ominous",
                "playful",
                "quirky",
                "upbeat",
            ],
            "intense": ["chaotic", "combat", "epic", "scary"],
        }
        try:
            parts = prompt.split("/")
            if len(parts) == 2:
                first, second = parts
            else:
                return "calm/adventerous"
            first = first.lower()
            second = second.lower()
            first_results = get_close_matches(first, valid_combinations.keys())
            if first_results:
                first = first_results[0]
            else:
                first = "calm"
            second_results = get_close_matches(
                second, valid_combinations[first]
            )
            if second_results:
                second = second_results[0]
            else:
                second = valid_combinations[first][0]
            if second not in valid_combinations[first]:
                second = valid_combinations[first][0]
            validated_mood = f"{first}/{second}"
            self.logger.info(f"Validated mood: {validated_mood}")
            return validated_mood
        except Exception as e:
            self.logger.error(f"Error validating mood prompt: {str(e)}")
            return "calm/adventerous"
