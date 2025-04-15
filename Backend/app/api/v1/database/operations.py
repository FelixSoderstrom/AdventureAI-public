"""
Class for all database operations.
Currently ongoing refactor.
Today we find all database operations within the same class.
I have ordered them into their respective 'category'.
Next step is to break these free into their own classes.
Check One-line docstrings within the class to see how the refactor will look once its done.
"""

# External imports
from sqlalchemy import select, insert, update, delete
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from psycopg2.errors import UniqueViolation
from fastapi import HTTPException
from typing import Dict, List, Any
from uuid import UUID
from datetime import datetime, timedelta
import re
import uuid
import bcrypt
import secrets
import base64

# Internal imports
from app.api.logger.loggable import Loggable
from app.api.v1.database.models import Table
from app.api.v1.validation.schemas import (
    UserCreate,
    SaveGame,
    UserLogin,
    UserUpdate,
)


class DatabaseOperations(Loggable):
    def __init__(self, db: Session):
        super().__init__()
        self.db = db
        self.logger.info("Database operations initialized with session")

    """
    USER MANAGER
    """

    def create_user(self, token: str) -> Dict[str:str]:
        """
        Posts a new user to the database with the information already stored in email_tokens.

        Args:
            token[str]: email-authorization token generated from the registration process.

        Raises/Handles:
            UniqueViolation, IntegrityError:
                When the code generated UUID already exists in the database. Because why not?

        Returns:
            access_token[str]: The actual authorization token.
                This gets stored in the client for future logins.
        """
        user_data = self._validate_email_token(token)
        self.logger.info(f"Creating new user: {user_data.email[:10]}...")
        for attempt in range(3):
            try:
                db_user = Table(
                    id=uuid.uuid4(),
                    email=user_data.email,
                    password=user_data.password,
                )
                self.db.add(db_user)
                self.db.commit()
                self.db.refresh(db_user)
                break
            except (UniqueViolation, IntegrityError):
                self.logger.error(
                    "Error posting to Users table due to UUID unique constraint. "
                    "If this happened, reality is a simulation."
                )
                if attempt == 2:
                    raise HTTPException(
                        status_code=500,
                        detail="User creation failed when posting to database.",
                    )
                continue
        access_token = self._create_access_token(db_user.id)
        return {"access_token": access_token}

    def login_user(self, user: UserLogin):
        """
        Logs in a user by creating a new authorization token.
        Activates a user if they are not active.

        Args:
            user[UserLogin]: The users login-data in a pydantic class.

        Raises:
            HTTPExc[401] when the credentials are invalid.
            HTTPExc[404] when user is not registered.
        """
        self.logger.info(f"Logging in user: {user.email[:10]}...")
        stmt = select(Table).where(Table.column == user.email)
        result = self.db.execute(stmt)
        db_user = result.scalar_one_or_none()
        if db_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        if not bcrypt.checkpw(
            user.password.encode("utf-8"), db_user.password.encode("utf-8")
        ):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if db_user.is_active is False:
            self.activate_user(db_user.id)
        token = self._create_access_token(user_id=db_user.id)
        return token

    def logout_user(self, user_id: UUID):
        """Logout a user by deleting their active tokens"""
        stmt = delete(Table).where(Table.column == user_id)
        self.db.execute(stmt)
        self.db.commit()
        self.logger.info(
            f"Removed all tokens for user ID: {str(user_id)[:10]}..."
        )

    def update_user(self, user_id: UUID, user: UserUpdate):
        """
        Updates a user in the database.
        If a new password is included it gets hashed.

        Args:
            user_id[UUID]: The user id extracted from authorization decorator
            user[UserUpdate]: The pydantic model for our new user.

        Raises:
            HTTPExc[404] when the user id does not exist in database.

        Returns:
            updated_user: The updated database row. Only returns if id exists in db.
        """
        nud = {}  # New-User-Data
        for key, value in user.model_dump().items():
            if value is not None:
                nud[key] = value
        if "password" in nud:
            nud["password"] = self._hash_password(nud["password"])
        stmt = (
            update(Table)
            .where(Table.column == user_id)
            .values(**nud)
            .returning(Table)
        )
        result = self.db.execute(stmt)
        updated_user = result.scalar_one_or_none()
        self.db.commit()
        if updated_user:
            return updated_user
        else:
            self.logger.critical(
                f"Token for user ID: {user_id} passed authorization check "
                "but the user_id does not exist in the database.\n"
                "Removing all tokens for this user.."
            )
            self.logout_user(user_id)
            raise HTTPException(
                status_code=404,
                detail="User not found",
            )

    def activate_user(self, user_id: UUID):
        """
        Activate a user by setting is_active to True
        This is done when an existing inavtive user logs in.

        Args:
            user_id[UUID]: The user id extracted from the authorization decorator.

        Raises:
            HTTPExc[404] if the user_id does not exist in db.
        """
        stmt = (
            update(Table)
            .where(Table.column == user_id)
            .values(is_active=True)
            .returning(Table)
        )
        result = self.db.execute(stmt)
        updated_user = result.scalar_one_or_none()
        self.db.commit()
        if updated_user is None:
            self.logger.critical(
                f"Token for user ID: {user_id} passed authorization check "
                "but the user_id does not exist in the database.\n"
                "Removing all tokens for this user.."
            )
            self.logout_user(user_id)
            raise HTTPException(
                status_code=404,
                detail="User not found",
            )

    def deactivate_user(self, user_id: UUID):
        """
        Deactivates a user by changing their is_active-column to False

        Args:
            user_id[UUID]: The id extracted from authorization decorator.

        Raises:
            HTTPExc[404] when a user_id was not found in db.
        """
        self.logout_user(user_id)
        stmt = (
            update(Table)
            .where(Table.column == user_id)
            .values(is_active=False)
            .returning(Table)
        )
        result = self.db.execute(stmt)
        updated_user = result.scalar_one_or_none()
        self.db.commit()
        if updated_user is None:
            self.logger.critical(
                f"A token tied to user ID: {user_id} successfully "
                "authenticated access to a protected endpoint (/soft_delete_user). "
                "But the user with this ID does not exist in the database. "
            )
            raise HTTPException(
                status_code=404,
                detail="User not found",
            )

    def hard_delete_user(self, user_id: UUID):
        """
        Hard deletes a user by removing their row from the database

        Args:
            user_id[UUID]: the id extracted from authorization decorator.

        Raises:
            HTTPExc[404]: If the user_id does nto exist in db.

        Returns:
            Dict[str:str]: Client response on successful deletion.
        """
        get_stmt = select(Table).where(Table.column == user_id)
        result = self.db.execute(get_stmt)
        user = result.scalar_one_or_none()
        email = user.email

        self.logout_user(user_id)
        delete_stmt = delete(Table).where(Table.column == user_id)
        result = self.db.execute(delete_stmt)
        if result.rowcount == 0:
            self.logger.critical(
                f"A token tied to user ID: {user_id} successfully "
                "authenticated access to a protected endpoint (/hard_delete_user). "
                "But the user with this ID does not exist in the database. "
            )
            raise HTTPException(
                status_code=404,
                detail="User not found",
            )
        else:
            self.db.commit()
            self.logger.info(
                f"Successfully deleted user ID: {str(user_id)[:10]}..."
            )
        self._delete_email_tokens(email)
        return {"message": "User deleted successfully"}

    def _validate_email(self, email: str) -> bool:
        """Validates email format. Returns True if valid."""
        self.logger.debug(f"Validating email format: {email[:5]}...")
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        is_valid = re.match(email_pattern, email)
        return bool(is_valid)

    def _check_existing_user(self, email: str) -> bool:
        """Checks if an email is registered. Returns True if user exists."""
        self.logger.debug(f"Checking if email: {email[:5]} exists...")
        stmt = select(Table).where(Table.column == email)
        result = self.db.execute(stmt)
        existing_user = result.scalar_one_or_none()
        return bool(existing_user)

    """
    TOKEN MANAGER
    """

    def generate_token(self) -> str:
        return "Wouldn't you like to know!"

    def _create_access_token(self, user_id: UUID) -> str:
        """Generates a new authorization token for a user and deletes all their previous tokens"""
        self.logger.debug(
            f"Creating access token for user ID: {str(user_id)[:10]}..."
        )
        self.logout_user(user_id)
        token = self.generate_token()
        expires_at = "some unknown timestamp"
        db_token = Table(token=token, expires_at=expires_at, user_id=user_id)
        self.db.add(db_token)
        self.db.commit()
        self.db.refresh(db_token)
        return token

    def validate_token(self, token: str) -> UUID:
        """
        Validates an authorization token and returns the user_id

        Args:
            token[str]: The authorization token from the client

        Raises:
            HTTPExc[401] when the token does not exist in db

        Returns:
            user_id[UUID]: If the token exists in db.
        """
        self.logger.info(f"Validating user token: {token[:10]}...")
        stmt = select(Table).where(Table.column == token)
        result = self.db.execute(stmt)
        token_data = result.scalar_one_or_none()
        if not token_data:
            raise HTTPException(
                status_code=401,
                detail="Invalid token",
            )
        else:
            user_id = token_data.user_id
            self.logger.info(
                f"Token validated for user: {str(user_id)[:10]}..."
            )
            return user_id

    def create_email_token(self, user: UserCreate) -> str:
        """
        Stores user data and new token in email_tokens on account registration.
        In the case where a user tries to register an account several times
        before activating it via the link, we handle it by making more links.

        Args:
            user[UserCreate]: The pydantic model for new user data.

        Raises:
            HTTPExc[400] If the Email is invalid or is already registered.

        Returns:
            token[str]: The email-token used for account activation via link.
        """
        if not self._validate_email(user.email):
            raise HTTPException(
                status_code=400,
                detail="Invalid email format",
            )
        if self._check_existing_user(user.email):
            raise HTTPException(
                status_code=400,
                detail="User with this email already exists",
            )
        try:
            token = self._post_email_token(user)
        except (UniqueViolation, IntegrityError):
            # If the user registers again before activating the old link.
            self.db.rollback()
            self._delete_email_tokens(email=user.email)
            token = self._post_email_token(user)
        return token

    def _post_email_token(self, user: UserCreate) -> str:
        """
        Creates a new email-token row for a user

        Args:
            user[UserCreate]: Pydantic model for user creation data.

        Returns:
            token[str]: The email token user in account registration-link.
        """
        hashed_pw = self._hash_password(user.password)
        token = self.generate_token()
        stmt = insert(Table).values(
            email=user.email,
            password=hashed_pw,
            token=token,
        )
        self.db.execute(stmt)
        self.db.commit()

        return token

    def _delete_email_tokens(self, email: str):
        """Deletes all emaikl-tokens for an email"""
        stmt = delete(Table).where(Table.column == email)
        self.db.execute(stmt)
        self.db.commit()

    def _validate_email_token(self, token: str) -> Table:
        """
        Checks if an email-token exists in the database.
        This method is used when the user clicks the link to activate their account.

        Args:
            token[str]: The email token

        Raises:
            HTTPExc[401]: If the token has expired
            HTTPExc[404]: If the token doesn't exist in the db.
        """
        stmt = select(Table).where(Table.column == token)
        result = self.db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="Token not found")
        if "The token timestamp is too old":
            self._delete_email_tokens(user.email)
            raise HTTPException(status_code=401, detail="Token expired")
        return user

    def update_email_token(self, email: str) -> str:
        """
        Generates and changes the email-token for a user
        This is used when the user wants to reset their password.

        Args:
            email[str]: The users email address

        Raises:
            HTTPExc[404]: When the email is not in the database

        Returns:
            new_token[str]: The new email-token
        """
        self.logger.info(f"Updating email token for user: {email[:5]}...")
        stmt = select(Table).where(Table.column == email)
        result = self.db.execute(stmt)
        token_data = result.scalar_one_or_none()
        if not token_data:
            raise HTTPException(status_code=404, detail="Email not registered")
        new_token = self.generate_token()
        stmt = (
            update(Table)
            .where(Table.column == email)
            .values(
                token=new_token,
                created_at=datetime.now(),
            )
        )
        self.db.execute(stmt)
        self.db.commit()
        return new_token

    def reset_password(self, token: str, password: str):
        """
        Changes a user's password.
        Used when user requests a password reset.

        Args:
            token[str]: The email-token from the reset-link.
            password[str]: The users new password
        """
        user_data = self._validate_email_token(token)
        hashed_pw = self._hash_password(password)
        stmt = (
            update(Table)
            .where(Table.column == user_data.email)
            .values(password=hashed_pw)
        )
        self.db.execute(stmt)
        self.db.commit()
        self.update_email_token(user_data.email)  # Makes link a one-time use
        return user_data

    def _hash_password(self, password: str) -> str:
        return "Super secret"

    """
    GAME MANAGER
    """

    def get_start_story(self, story_id: str):
        """
        Retrieves a starting story from the database

        Args:
            story_id[str]: The id of the database row we want to fetch.

        Raises:
            HTTPExc[404]: If the ID doesnt exist in db.

        Returns:
            Dict[str:str]: The client response including the requested story.
        """
        self.logger.info(f"Getting story with ID: {story_id}")

        stmt = select(Table).where(Table.column == story_id)
        result = self.db.execute(stmt)
        starting_story = result.scalar_one_or_none()

        if starting_story.story is None or starting_story.image is None:
            self.logger.error(f"Story with ID {story_id} not found")
            raise HTTPException(
                status_code=404,
                detail=f"Story with ID {story_id} not found",
            )
        return {
            "image": starting_story.image,
            "story": starting_story.story,
            "id": starting_story.id,
        }

    def load_game(self, user_id: str):
        """
        Gets all game sessions from a user

        Args:
            user_id[str]: The UUID extracted from authorization decorator.

        Returns:
            response_data[List[Dict]]: All game sessions
        """
        stmt = select(Table).where(Table.column == user_id)
        result = self.db.execute(stmt)
        all_saves: List[Table] = result.scalars().all()
        response_data = []
        for save in all_saves:
            response_data.append(
                {
                    "id": save.id,
                    "protagonist_name": save.protagonist_name,
                    "inventory": save.inventory,
                    "session_name": save.session_name,
                    "stories": save.stories,
                    "image": save.last_image,
                    "last_played": save.updated_at,
                }
            )
        return response_data

    def get_user_profile(self, user_id: UUID) -> Dict[str, Any]:
        """
        Gets a user's profile information

        Args:
            user_id[UUID]: The ID extracted from authorization decorator

        Raises:
            HTTPExc[404]: If the user_id didnt exist in db.

        Returns:
            Dict[str:str]: The relevant user data.
        """
        stmt = select(Table).where(Table.column == user_id)
        result = self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        created_date = (
            user.created_at.strftime("%Y-%m-%d") if user.created_at else None
        )

        return {
            "email": user.email,
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "registered_at": created_date,
        }

    def save_game_route(self, data: SaveGame, user_id):
        """
        Routes a game session to be saved in either a new or existing db row.

        Args:
            data[SaveGame]: The game session we want to save
            user_id[str]: The ID extracted from authorization decorator

        Returns:
            game_id[str]: The ID if the saved game session.
        """
        # Saving to a new row
        if data.game_session.id is None:
            stmt = (
                insert(Table)
                .values(
                    user_id=user_id,
                    last_image=data.image,
                    protagonist_name=data.game_session.protagonist_name,
                    session_name=data.game_session.session_name,
                    inventory=data.game_session.inventory,
                    stories=data.game_session.scenes,
                )
                .returning(Table.column)
            )
            result = self.db.execute(stmt)
            game_id = result.scalar_one()

        # Saving to an existing row
        else:
            existing_stmt = select(Table.column).where(
                Table.column == data.game_session.id
            )
            result = self.db.execute(existing_stmt)
            old_scenes = result.scalar_one_or_none()
            updated_scenes = old_scenes + data.game_session.scenes
            stmt = (
                update(Table)
                .where(Table.column == data.game_session.id)
                .values(
                    last_image=data.image,
                    session_name=data.game_session.session_name,
                    inventory=data.game_session.inventory,
                    stories=updated_scenes,
                )
            )
            self.db.execute(stmt)
            game_id = data.game_session.id

        self.db.commit()

        return game_id
