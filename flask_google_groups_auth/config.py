"""Configuration management for flask_google_groups_auth module.

Handles service account key file and Secret Manager integration.
If an environment variable is not set, the library will automatically attempt
to fetch from Secret Manager using the same name as the environment variable.
"""

import json
import os
import secrets
from typing import Optional

import google.auth
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
        self._service_account_info: Optional[dict] = None
        self._delegated_admin_email: Optional[str] = None
        self._client_id: Optional[str] = None
        self._client_secret: Optional[str] = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """
        Initialize the Flask application with this config.
        
        Resolves all configuration values up front from:
        1. Environment variables
        2. Google Cloud Secret Manager (if env var not set)
        3. None (if neither available)
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Store config in app extensions
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['flask_google_groups_auth'] = self
        
        # Resolve all configuration values up front
        app.config.setdefault('SERVICE_ACCOUNT_KEY_FILE', self._resolve_config('SERVICE_ACCOUNT_KEY_FILE'))
        app.config.setdefault('DELEGATED_ADMIN_EMAIL', self._resolve_config('DELEGATED_ADMIN_EMAIL'))
        app.config.setdefault('GOOGLE_CLIENT_ID', self._resolve_config('GOOGLE_CLIENT_ID'))
        app.config.setdefault('GOOGLE_CLIENT_SECRET', self._resolve_config('GOOGLE_CLIENT_SECRET'))
        app.config.setdefault('REDIRECT_URI', self._resolve_config('REDIRECT_URI'))
        app.config.setdefault('SECRET_KEY', self._resolve_config('SECRET_KEY'))
        app.logger.info("Configuration initialized for flask_google_groups_auth")
        app.logger.debug(f"App config: {app.config}")
        
        # Set Flask secret key with fallback to auto-generation
        if not app.secret_key:
            secret_key = app.config.get('SECRET_KEY')
            if secret_key:
                app.secret_key = secret_key
            else:
                # Auto-generate only if nothing is configured
                app.logger.warning(
                    "No SECRET_KEY configured. Auto-generating one, but this will invalidate "
                    "sessions on restart. Set SECRET_KEY environment variable or store in Secret Manager."
                )
                app.secret_key = secrets.token_hex(32)
        
        # Configure secure session cookies
        app.config.setdefault('SESSION_COOKIE_SECURE', not app.debug)  # HTTPS only in production
        app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)  # Prevent JavaScript access
        app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')  # CSRF protection
        
        # Set session lifetime (default: 24 hours)
        app.config.setdefault('PERMANENT_SESSION_LIFETIME', 86400)
        
        # Group membership cache configuration
        app.config.setdefault('CACHE_TTL', 3600)  # 1 hour default
        app.extensions['group_membership_cache'] = {}  # Server-side cache
    
    def _resolve_config(self, name: str) -> Optional[str]:
        """
        Resolve configuration value from environment variable or Secret Manager.
        
        Tries in order:
        1. Environment variable
        2. Secret Manager (using same name)
        3. Returns None if neither available
        
        Args:
            name: The name to use for both env var and Secret Manager secret
            
        Returns:
            The configuration value or None if not found
        """
        # Try environment variable first
        value = os.getenv(name)
        if value:
            self.app.logger.info(f"Loaded {name} from environment variable")
            return value
        
        # Try Secret Manager
        self.app.logger.info(f"Environment variable {name} not set, trying Secret Manager")
        try:
            value = self.get_secret(name)
            # self.app.logger.info(f"Successfully loaded {name} from Secret Manager (length: {len(value)})")
            self.app.logger.info(f"Successfully loaded {name} from Secret Manager (value: {value})")
            return value
        except Exception as e:
            self.app.logger.debug(f"Could not load {name} from Secret Manager: {type(e).__name__}: {e}")
            return None
    
    def get_secret(self, secret_id: str, project_id: Optional[str] = None) -> str:
        """
        Retrieve a secret from Google Cloud Secret Manager.
        
        Uses Application Default Credentials (ADC) to automatically determine
        the project if not explicitly provided.
        
        Args:
            secret_id: The ID of the secret to retrieve
            project_id: GCP project ID (optional, uses ADC if not provided)
            
        Returns:
            The secret value as a string
        """
        self.app.logger.info(f"Fetching secret: {secret_id}")
        
        # Get project ID from parameter or ADC
        if not project_id:
            try:
                credentials, project_id = google.auth.default()
                self.app.logger.info(f"Got credentials, project_id from default(): {project_id}")
            except Exception as e:
                self.app.logger.error(f"Failed to get default credentials: {type(e).__name__}: {e}")
                raise
                
            # Also try quota_project_id if project_id is None
            if not project_id and hasattr(credentials, 'quota_project_id'):
                project_id = credentials.quota_project_id
                self.app.logger.info(f"Using quota_project_id: {project_id}")
                
            # Try environment variables as fallback
            if not project_id:
                project_id = os.getenv('GOOGLE_CLOUD_PROJECT') or os.getenv('GCP_PROJECT') or os.getenv('GCLOUD_PROJECT')
                if project_id:
                    self.app.logger.info(f"Using project_id from environment: {project_id}")
                    
            if not project_id:
                raise ValueError(
                    "Cannot determine GCP project ID. Either:\n"
                    "  - Run 'gcloud config set project YOUR_PROJECT_ID'\n"
                    "  - Set GOOGLE_CLOUD_PROJECT environment variable\n"
                    "  - Provide project_id parameter"
                )

        self.app.logger.info(f"Using project_id: {project_id}")
        
        # Use context manager to ensure client is properly closed
        try:
            with secretmanager.SecretManagerServiceClient() as client:
                name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
                self.app.logger.info(f"Accessing secret: {name}")
                response = client.access_secret_version(request={"name": name})
                secret_value = response.payload.data.decode('UTF-8')
                self.app.logger.info(f"Successfully retrieved secret {secret_id} (length: {len(secret_value)})")
                return secret_value
        except Exception as e:
            self.app.logger.error(f"Error accessing secret {secret_id}: {type(e).__name__}: {e}")
            raise
    
    def get_service_account_info(self) -> dict:
        """
        Get service account credentials from key file or Secret Manager.
        
        The SERVICE_ACCOUNT_KEY_FILE config value can be:
        1. A file path to a local JSON key file
        2. JSON content directly from Secret Manager
        
        Returns:
            Dictionary with service account credentials (parsed JSON)
            
        Raises:
            ValueError: If service account key is not configured
        """
        if self._service_account_info is None:
            key_file = self.app.config.get('SERVICE_ACCOUNT_KEY_FILE')
            
            if not key_file:
                raise ValueError(
                    "Service account key not configured. Set either:\n"
                    "  - SERVICE_ACCOUNT_KEY_FILE environment variable (path to JSON file), or\n"
                    "  - Store service account JSON in Secret Manager as 'SERVICE_ACCOUNT_KEY_FILE'"
                )
            
            # Check if it's a file path
            if os.path.exists(key_file):
                self.app.logger.info(f"Loading service account key from file: {key_file}")
                with open(key_file, 'r') as f:
                    self._service_account_info = json.load(f)
            else:
                # Treat it as JSON content from Secret Manager
                self.app.logger.info("Parsing service account key as JSON from Secret Manager")
                try:
                    self._service_account_info = json.loads(key_file)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"SERVICE_ACCOUNT_KEY_FILE is neither a valid file path nor valid JSON: {e}"
                    )
        
        return self._service_account_info
    
    def get_delegated_admin_email(self) -> str:
        """
        Get delegated admin email from config (resolved from env var or Secret Manager).
        
        Returns:
            The delegated admin email address
            
        Raises:
            ValueError: If not configured
        """
        if self._delegated_admin_email is None:
            self._delegated_admin_email = self.app.config.get('DELEGATED_ADMIN_EMAIL')
            
            if not self._delegated_admin_email:
                raise ValueError(
                    "Delegated admin email not configured. Set either:\n"
                    "  - DELEGATED_ADMIN_EMAIL environment variable, or\n"
                    "  - Store email in Secret Manager as 'DELEGATED_ADMIN_EMAIL'"
                )
        
        return self._delegated_admin_email
    
    def get_client_id(self) -> str:
        """
        Get Google OAuth client ID from config (resolved from env var or Secret Manager).
        
        Returns:
            The OAuth client ID
            
        Raises:
            ValueError: If not configured
        """
        if self._client_id is None:
            self._client_id = self.app.config.get('GOOGLE_CLIENT_ID')
            
            if not self._client_id:
                raise ValueError(
                    "Google OAuth client ID not configured. Set either:\n"
                    "  - GOOGLE_CLIENT_ID environment variable, or\n"
                    "  - Store client ID in Secret Manager as 'GOOGLE_CLIENT_ID'"
                )
        
        return self._client_id
    
    def get_client_secret(self) -> str:
        """
        Get Google OAuth client secret from config (resolved from env var or Secret Manager).
        
        Returns:
            The OAuth client secret
            
        Raises:
            ValueError: If not configured
        """
        if self._client_secret is None:
            self._client_secret = self.app.config.get('GOOGLE_CLIENT_SECRET')
            
            if not self._client_secret:
                raise ValueError(
                    "Google OAuth client secret not configured. Set either:\n"
                    "  - GOOGLE_CLIENT_SECRET environment variable, or\n"
                    "  - Store client secret in Secret Manager as 'GOOGLE_CLIENT_SECRET'"
                )
        
        return self._client_secret
    
    def get_redirect_uri(self) -> str:
        """
        Get OAuth redirect URI from config (resolved from env var or Secret Manager).
        
        Returns:
            The redirect URI
            
        Raises:
            ValueError: If not configured
        """
        redirect_uri = self.app.config.get('REDIRECT_URI')
        
        if not redirect_uri:
            raise ValueError(
                "Redirect URI not configured. Set either:\n"
                "  - REDIRECT_URI environment variable, or\n"
                "  - Store redirect URI in Secret Manager as 'REDIRECT_URI'"
            )
        
        return redirect_uri
    
    def get_oauth_config(self) -> dict:
        """
        Get OAuth configuration.
        
        Returns:
            Dictionary with client_id, client_secret, and redirect_uri
        """
        return {
            'client_id': self.get_client_id(),
            'client_secret': self.get_client_secret(),
            'redirect_uri': self.get_redirect_uri(),
        }
