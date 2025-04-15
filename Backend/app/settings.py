"""
Pydantic settings for environment variables.
Make sure your env file has all of these below.
Import 'settings' (the instance, not the class) into other modules.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    DB_URL: str
    OPENAI_API_KEY: str
    SD_ENDPOINT: str
    SD_API_KEY: str
    MISTRAL_ENDPOINT: str
    MAILGUN_API_KEY: str
    MAILGUN_DOMAIN: str
    MAILGUN_EMAIL: str
    FRONTEND_URL: str
    SD_EC2_ID: str
    START_LAMBDA_NAME: str
    REGION: str


settings = Settings()
