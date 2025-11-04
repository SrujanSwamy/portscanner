"""Application configuration.

Contains secrets and SMTP settings used by the backend. For production,
avoid hard-coding sensitive values—prefer environment variables or a
secrets manager.
"""

import os

# Flask secret key (use an environment variable in production)
SECRET_KEY = 'your_secret_key_here'

# Outbound email credentials (use app password; prefer env vars in production)
EMAIL_ADDRESS = 'example@gmail.com'
EMAIL_PASSWORD = 'example_password'

# SMTP server configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
