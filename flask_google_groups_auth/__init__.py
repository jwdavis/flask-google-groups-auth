"""
Google Auth and Group Check Module for Flask

This module provides Flask decorators and utilities for:
1. Google OAuth authentication
2. Checking Google Group membership (supports single or multiple groups)
3. Protecting routes based on authentication and group membership
4. Nested group membership support (including external members across domains)

Designed for Cloud Run deployment with service account domain-wide delegation (DWD).

The module uses a simplified authentication approach:
- Local Development: Service account key file from filesystem
- Cloud Run: Service account key JSON from Secret Manager
- OAuth credentials from environment variables
- Cloud Identity API for nested group membership checks
"""

from .config import Config
from .decorators import require_auth, require_group_member

__version__ = "0.5.0"
__all__ = ["require_auth", "require_group_member", "Config"]
