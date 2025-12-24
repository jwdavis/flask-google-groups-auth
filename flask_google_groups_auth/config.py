"""Configuration management for flask_google_groups_auth module.

Handles Secret Manager integration and configuration loading.
"""

import os
import secrets
from typing import Optional

from google.cloud import secretmanager


class Config:
    """Configuration manager for the flask_google_groups_auth module."""
    
    def __init__(self, app=None):
        """
        Initialize configuration.
        
        Args:
            app: Flask application instance (optional)
        """
        self.app = app
        self._delegated_admin_email: Optional[str] = None
        self._client_id: Optional[str] = None
        self._client_secret: Optional[str] = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """
        Initialize the Flask application with this config.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Store config in app extensions
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['flask_google_groups_auth'] = self
        
        # Set default configuration
        app.config.setdefault('FLASK_GOOGLE_GROUPS_AUTH_PROJECT_ID', os.getenv('GCP_PROJECT_ID'))
        
        # Secret Manager secret IDs (optional, falls back to env vars)
        app.config.setdefault('FLASK_GOOGLE_GROUPS_AUTH_DELEGATED_ADMIN_EMAIL_SECRET_NAME', os.getenv('DELEGATED_ADMIN_EMAIL_SECRET_NAME'))
        app.config.setdefault('FLASK_GOOGLE_GROUPS_AUTH_CLIENT_ID_SECRET_NAME', os.getenv('GOOGLE_CLIENT_ID_SECRET_NAME'))
        app.config.setdefault('FLASK_GOOGLE_GROUPS_AUTH_CLIENT_SECRET_SECRET_NAME', os.getenv('GOOGLE_CLIENT_SECRET_SECRET_NAME'))
        
        # Direct env vars (fallback if Secret Manager not configured)
        app.config.setdefault('FLASK_GOOGLE_GROUPS_AUTH_ADMIN_EMAIL_ENV', os.getenv('DELEGATED_ADMIN_EMAIL'))
        app.config.setdefault('FLASK_GOOGLE_GROUPS_AUTH_CLIENT_ID_ENV', os.getenv('GOOGLE_CLIENT_ID'))
        app.config.setdefault('FLASK_GOOGLE_GROUPS_AUTH_CLIENT_SECRET_ENV', os.getenv('GOOGLE_CLIENT_SECRET'))
        app.config.setdefault('FLASK_GOOGLE_GROUPS_AUTH_REDIRECT_URI', os.getenv('REDIRECT_URI', '/auth/callback'))
        
        # Auto-generate a random secret key for sessions if not set
        # WARNING: This should be set to a persistent value in production!
        if not app.secret_key:
            app.logger.warning(
                "No SECRET_KEY configured. Auto-generating one, but this will invalidate "
                "sessions on restart. Set SECRET_KEY environment variable in production."
            )
            app.secret_key = secrets.token_hex(32)
        
        # Configure secure session cookies
        # These settings protect against session hijacking and CSRF attacks
        app.config.setdefault('SESSION_COOKIE_SECURE', not app.debug)  # HTTPS only in production
        app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)  # Prevent JavaScript access
        app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')  # CSRF protection
        
        # Set session lifetime (default: 24 hours)
        app.config.setdefault('PERMANENT_SESSION_LIFETIME', 86400)
        
        # Group membership cache configuration
        app.config.setdefault('FLASK_GOOGLE_GROUPS_AUTH_CACHE_TTL', 3600)  # 1 hour default
        app.extensions['group_membership_cache'] = {}  # Server-side cache
    
    def get_secret(self, secret_id: str, project_id: Optional[str] = None) -> str:
        """
        Retrieve a secret from Google Cloud Secret Manager.
        
        Uses context manager to ensure proper client cleanup.
        
        Args:
            secret_id: The ID of the secret to retrieve
            project_id: GCP project ID (uses app config if not provided)
            
        Returns:
            The secret value as a string
            
        Raises:
            ValueError: If project_id is not configured
        """
        if project_id is None:
            project_id = self.app.config.get('FLASK_GOOGLE_GROUPS_AUTH_PROJECT_ID')
        
        if not project_id:
            raise ValueError("GCP project ID not configured")
        
        # Build the resource name
        name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
        
        # Use context manager to ensure client is properly closed
        with secretmanager.SecretManagerServiceClient() as client:
            response = client.access_secret_version(request={"name": name})
            return response.payload.data.decode('UTF-8')
    
    def get_delegated_admin_email(self) -> str:
        """
        Get the delegated admin email from Secret Manager or environment variable.
        
        Tries Secret Manager first (if secret ID configured), falls back to env var.
        
        Returns:
            The delegated admin email address
            
        Raises:
            ValueError: If neither Secret Manager nor env var is configured
        """
        if self._delegated_admin_email is None:
            # Try Secret Manager first
            secret_id = self.app.config.get('FLASK_GOOGLE_GROUPS_AUTH_DELEGATED_ADMIN_EMAIL_SECRET_NAME')
            if secret_id:
                self._delegated_admin_email = self.get_secret(secret_id)
            else:
                # Fall back to environment variable
                self._delegated_admin_email = self.app.config.get('FLASK_GOOGLE_GROUPS_AUTH_ADMIN_EMAIL_ENV')
            
            if not self._delegated_admin_email:
                raise ValueError(
                    "Delegated admin email not configured. "
                    "Set DELEGATED_ADMIN_EMAIL_SECRET_NAME (for Secret Manager) or DELEGATED_ADMIN_EMAIL (env var)"
                )
        return self._delegated_admin_email
    
    def get_client_id(self) -> str:
        """
        Get Google OAuth client ID from Secret Manager or environment variable.
        
        Tries Secret Manager first (if secret ID configured), falls back to env var.
        
        Returns:
            The OAuth client ID
            
        Raises:
            ValueError: If neither Secret Manager nor env var is configured
        """
        if self._client_id is None:
            # Try Secret Manager first
            secret_id = self.app.config.get('FLASK_GOOGLE_GROUPS_AUTH_CLIENT_ID_SECRET_NAME')
            if secret_id:
                self._client_id = self.get_secret(secret_id)
            else:
                # Fall back to environment variable
                self._client_id = self.app.config.get('FLASK_GOOGLE_GROUPS_AUTH_CLIENT_ID_ENV')
            
            if not self._client_id:
                raise ValueError(
                    "Google OAuth client ID not configured. "
                    "Set GOOGLE_CLIENT_ID_SECRET_NAME (for Secret Manager) or GOOGLE_CLIENT_ID (env var)"
                )
        return self._client_id
    
    def get_client_secret(self) -> str:
        """
        Get Google OAuth client secret from Secret Manager or environment variable.
        
        Tries Secret Manager first (if secret ID configured), falls back to env var.
        
        Returns:
            The OAuth client secret
            
        Raises:
            ValueError: If neither Secret Manager nor env var is configured
        """
        if self._client_secret is None:
            # Try Secret Manager first
            secret_id = self.app.config.get('FLASK_GOOGLE_GROUPS_AUTH_CLIENT_SECRET_SECRET_NAME')
            if secret_id:
                self._client_secret = self.get_secret(secret_id)
            else:
                # Fall back to environment variable
                self._client_secret = self.app.config.get('FLASK_GOOGLE_GROUPS_AUTH_CLIENT_SECRET_ENV')
            
            if not self._client_secret:
                raise ValueError(
                    "Google OAuth client secret not configured. "
                    "Set GOOGLE_CLIENT_SECRET_SECRET_NAME (for Secret Manager) or GOOGLE_CLIENT_SECRET (env var)"
                )
        return self._client_secret
    
    def get_oauth_config(self) -> dict:
        """
        Get OAuth configuration.
        
        Returns:
            Dictionary with client_id, client_secret, and redirect_uri
        """
        return {
            'client_id': self.get_client_id(),
            'client_secret': self.get_client_secret(),
            'redirect_uri': self.app.config.get('FLASK_GOOGLE_GROUPS_AUTH_REDIRECT_URI'),
        }
