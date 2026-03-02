"""
Email Service

Sends password reset codes and other transactional emails via SMTP.
Falls back to logging when SMTP is not configured.
"""

import secrets
import structlog
from aiosmtplib import send as smtp_send
from email.message import EmailMessage

from app.core.config import settings

logger = structlog.get_logger()


def generate_reset_code(length: int = 6) -> str:
    """Generate a numeric reset code."""
    return "".join([str(secrets.randbelow(10)) for _ in range(length)])


async def send_reset_email(to_email: str, code: str) -> bool:
    """
    Send a password-reset code to the given email address.

    Returns True if the email was sent (or logged in dev mode), False on error.
    """
    subject = f"SentinelAI — Password Reset Code: {code}"
    body = (
        f"Your SentinelAI password reset code is:\n\n"
        f"    {code}\n\n"
        f"This code is valid for 15 minutes.\n"
        f"If you did not request a password reset, please ignore this email.\n\n"
        f"— SentinelAI Security Team"
    )

    # If SMTP is not configured, just log the code (dev mode)
    if not settings.SMTP_HOST:
        logger.warning(
            "SMTP not configured — logging reset code",
            email=to_email,
            code=code,
        )
        return True

    try:
        msg = EmailMessage()
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        await smtp_send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER or None,
            password=settings.SMTP_PASSWORD or None,
            use_tls=settings.SMTP_USE_TLS,
        )
        logger.info("Password reset email sent", email=to_email)
        return True

    except Exception as e:
        logger.error("Failed to send reset email", email=to_email, error=str(e))
        return False
