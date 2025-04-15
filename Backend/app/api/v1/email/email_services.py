# External imports
import requests
from fastapi import HTTPException

# Internal imports
from app.api.logger.loggable import Loggable
from app.settings import settings


class EmailServices(Loggable):
    def __init__(self):
        super().__init__()
        self.logger.info("Email services initialized")

    def send_activation_email(self, email: str, token: str):
        """
        Sends an email to the user with a registration link

        Args:
            email[str]: The recipient
            token[str]: The email token used to build link and register account.

        Raises:
            HTTPExc[500]: When email service fails (email api does not return 200)
        """
        email_url = f"www.{settings.MAIL_DOMAIN}.whoknows"
        activation_link = f"{settings.FRONTEND_URL}/some_endpoint/{token}"

        html_content = f"""
            <h2>Welcome to Adventure AI!</h2>
            <p>Thank you for registering. To activate your account, please click the link below:</p>
            <p><a href="{activation_link}">Activate Your Account</a></p>
            <p><strong>Please note:</strong> This activation link will expire in 60 minutes.</p>
            <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
            <p>{activation_link}</p>
            <br>
            <p>If you didn't request this registration, please ignore this email.</p>
        """

        response = requests.post(
            email_url,
            auth=(
                "api",
                settings.EMAIL_API_KEY,
            ),
            data={
                "from": f"Adventure AI <{settings.EMAIL_ADDRESS}>",
                "to": email,
                "subject": "Activate Your Adventure AI Account",
                "html": html_content,
                "text": f"Welcome to Adventure AI!\n\n"
                f"Please click the following link to activate your account:\n"
                f"{activation_link}\n\n"
                f"Note: This activation link will expire in 60 minutes.\n\n"
                f"If you didn't request this registration, please ignore this email.",
            },
        )

        if response.status_code != 200:
            self.logger.error(
                f"Failed to send activation email: {response.text}"
            )
            raise HTTPException(
                status_code=500, detail="Failed to send activation email"
            )

    def send_reset_email(self, email: str, token: str):
        """
        Sends an email to the user with a password reset link

        Args:
            email[str]: The recipient
            token[str]: Used to build the link and authorization for password reset.

        Raises:
            HTTPExc[500] When the email service fails (api does not return 200)
        """
        email_url = f"www.{settings.EMAIL_DOMAIN}.whoknows"
        reset_link = f"{settings.FRONTEND_URL}/some_endpoint/{token}"

        html_content = f"""
            <h2>Reset Your Adventure AI Password</h2>
            <p>We received a request to reset your Adventure AI password. To proceed, please click the link below:</p>
            <p><a href="{reset_link}">Reset Your Password</a></p>
            <p><strong>Please note:</strong> This reset link will expire in 60 minutes.</p>
            <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
            <p>{reset_link}</p>
            <br>
            <p>If you didn't request this password reset, please ignore this email.</p>
        """

        response = requests.post(
            email_url,
            auth=(
                "api",
                settings.EMAIL_API_KEY,
            ),
            data={
                "from": f"Adventure AI <{settings.EMAIL_ADDRESS}>",
                "to": email,
                "subject": "Reset Your Adventure AI Password",
                "html": html_content,
                "text": f"We received a request to reset your Adventure AI password. To proceed, please click the following link:\n"
                f"{reset_link}\n\n"
                f"Note: This reset link will expire in 60 minutes.\n\n"
                f"If you didn't request this password reset, please ignore this email.",
            },
        )

        if response.status_code != 200:
            self.logger.error(f"Failed to send reset email: {response.text}")
            raise HTTPException(
                status_code=500, detail="Failed to send reset email"
            )
