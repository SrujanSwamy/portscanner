"""Authentication helpers: OTP email sending and JWT token validation.

Provides utilities for sending one-time passwords (OTP) via SMTP and a
Flask route decorator to enforce JWT-based authentication.
"""

import smtplib
from email.message import EmailMessage
import jwt
from functools import wraps
from flask import request, jsonify
from config import (EMAIL_ADDRESS, EMAIL_PASSWORD,
                    SMTP_SERVER, SMTP_PORT, SECRET_KEY)


def send_otp_email(to_email, otp):
    """Send a plain-text OTP email.

    Args:
        to_email (str): Recipient email address.
        otp (str): One-time password (valid for a limited time).

    Returns:
        bool: True if the email was sent, otherwise False.
    """
    try:
        msg = EmailMessage()
        msg.set_content(
            f'Your verification OTP is: {otp}\n\n'
            f'It is valid for 10 minutes.')
        msg['Subject'] = 'Port Scanner - Verify Your Email'
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"OTP email sent to {to_email}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


# --- JWT Token Decorator ---
def token_required(f):
    """Decorator to protect routes requiring a valid JWT.

    Expects an Authorization header with the format: "Bearer <token>".
    Returns 401 with a short message on missing/invalid/expired token.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                # Expect: Authorization: Bearer <token>
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token is invalid!'}), 401

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)
    return decorated
