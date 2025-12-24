"""
Google Auth and Group Check Module for Flask

This module provides Flask decorators and utilities for:
1. Forcing Google authentication
2. Checking Google Group membership (supports single or multiple groups)
3. Protecting routes based on authentication and group membership

Designed for Cloud Run deployment with service account domain-wide delegation.

The module now supports checking membership in a list of groups with OR logic:
- Users need to be in at least ONE of the specified groups to gain access
- Groups can be configured via Secret Manager (comma-separated) or passed directly to decorators
"""

from .config import Config
from .decorators import require_auth, require_group_member

__version__ = "0.2.0"
__all__ = ["require_auth", "require_group_member", "Config"]
