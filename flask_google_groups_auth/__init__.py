"""
Google Auth and Group Check Module for Flask

This module provides Flask decorators and utilities for:
1. Google OAuth authentication
2. Checking Google Group membership (supports single or multiple groups)
3. Protecting routes based on authentication and group membership

Designed for Cloud Run deployment with service account domain-wide delegation (DWD).

The module uses a simplified authentication approach:
- Local Development: Service account key file from filesystem
- Cloud Run: Service account key JSON from Secret Manager
- OAuth credentials from environment variables
"""

from .config import Config
from .decorators import require_auth, require_group_member

__version__ = "0.3.0"
__all__ = ["require_auth", "require_group_member", "Config"]
