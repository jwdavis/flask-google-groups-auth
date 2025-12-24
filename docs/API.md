# API Reference

Complete API documentation for `flask-google-groups-auth`.

## Table of Contents

- [Configuration](#configuration)
- [Decorators](#decorators)
- [Authentication Functions](#authentication-functions)
- [Group Check Functions](#group-check-functions)
- [Exceptions](#exceptions)
- [Configuration Keys](#configuration-keys)

## Configuration

### `Config`

Configuration manager for the flask_google_groups_auth module.

```python
from flask_google_groups_auth import Config

config = Config(app)
```

#### `__init__(app=None)`

Initialize configuration.

**Parameters:**
- `app` (Flask, optional): Flask application instance. If provided, calls `init_app()` automatically.

**Example:**
```python
# Option 1: Initialize with app
app = Flask(__name__)
config = Config(app)

# Option 2: Initialize separately
config = Config()
config.init_app(app)
```

#### `init_app(app)`

Initialize the Flask application with this config. Sets up secure session cookies, default configuration values, and cache.

**Parameters:**
- `app` (Flask): Flask application instance

**Side Effects:**
- Stores config in `app.extensions['flask_google_groups_auth']`
- Sets session cookie security settings
- Initializes server-side cache
- Auto-generates `SECRET_KEY` if not set (with warning)

#### `get_secret(secret_id, project_id=None)`

Retrieve a secret from Google Cloud Secret Manager.

**Parameters:**
- `secret_id` (str): The ID of the secret to retrieve
- `project_id` (str, optional): GCP project ID. Uses `FLASK_GOOGLE_GROUPS_AUTH_PROJECT_ID` if not provided.

**Returns:**
- `str`: The secret value

**Raises:**
- `ValueError`: If project_id is not configured

**Example:**
```python
delegated_email = config.get_secret('delegated-admin-email')
```

#### `get_delegated_admin_email()`

Get the delegated admin email from Secret Manager or environment variable.

**Returns:**
- `str`: The delegated admin email address

**Raises:**
- `ValueError`: If neither Secret Manager nor environment variable is configured

**Priority:**
1. Secret Manager (if `FLASK_GOOGLE_GROUPS_AUTH_DELEGATED_ADMIN_EMAIL_SECRET_NAME` configured)
2. Environment variable (`DELEGATED_ADMIN_EMAIL`)

#### `get_client_id()`

Get Google OAuth client ID from Secret Manager or environment variable.

**Returns:**
- `str`: The OAuth client ID

**Raises:**
- `ValueError`: If neither Secret Manager nor environment variable is configured

#### `get_client_secret()`

Get Google OAuth client secret from Secret Manager or environment variable.

**Returns:**
- `str`: The OAuth client secret

**Raises:**
- `ValueError`: If neither Secret Manager nor environment variable is configured

#### `get_oauth_config()`

Get complete OAuth configuration.

**Returns:**
- `dict`: Dictionary with keys:
  - `client_id` (str): OAuth client ID
  - `client_secret` (str): OAuth client secret
  - `redirect_uri` (str): OAuth redirect URI

## Decorators

### `@require_auth`

Decorator that requires a user to be authenticated.

**Behavior:**
- If user is not authenticated: redirects to login page
- After successful login: redirects back to original page
- If user is authenticated: allows access

**Example:**
```python
from flask_google_groups_auth import require_auth

@app.route('/dashboard')
@require_auth
def dashboard():
    user = get_current_user()
    return f"Hello, {user['name']}!"
```

### `@require_group_member(groups)`

Decorator that requires authentication AND group membership.

**Parameters:**
- `groups` (str or list): Single group email or list of group emails. User must be in at least one group (OR logic).

**Behavior:**
- If not authenticated: redirects to login page
- If authenticated but not in any required group: returns 403 Forbidden
- If authenticated and in at least one group: allows access

**Example:**
```python
from flask_google_groups_auth import require_group_member

# Single group
@app.route('/admin')
@require_group_member('admins@example.com')
def admin():
    return "Admin panel"

# Multiple groups (OR logic)
@app.route('/content')
@require_group_member(['editors@example.com', 'admins@example.com'])
def content():
    return "Content area"
```

**Logging:**
- Logs warning when user attempts to access but lacks group membership
- Includes user email, path, and required groups

### `@optional_auth`

Decorator that makes authentication optional but provides user info if authenticated.

**Behavior:**
- Always allows access
- User info available via `get_current_user()` if logged in

**Example:**
```python
from flask_google_groups_auth.decorators import optional_auth
from flask_google_groups_auth.auth import get_current_user

@app.route('/welcome')
@optional_auth
def welcome():
    user = get_current_user()
    if user:
        return f"Hello, {user['name']}!"
    return "Hello, guest!"
```

## Authentication Functions

### `setup_auth_routes(app)`

Set up authentication routes for the Flask app. Must be called once during app initialization.

**Parameters:**
- `app` (Flask): Flask application instance

**Routes Created:**
- `GET /auth/login`: Initiate Google OAuth login
- `GET /auth/callback`: Handle OAuth callback from Google
- `GET /auth/logout`: Log out current user

**Example:**
```python
from flask_google_groups_auth.auth import setup_auth_routes

app = Flask(__name__)
config = Config(app)
setup_auth_routes(app)  # Sets up auth routes
```

### `is_authenticated()`

Check if the current user is authenticated.

**Returns:**
- `bool`: True if user is authenticated, False otherwise

**Example:**
```python
from flask_google_groups_auth.auth import is_authenticated

if is_authenticated():
    print("User is logged in")
```

### `get_current_user()`

Get current authenticated user information.

**Returns:**
- `dict` or `None`: User information dictionary if authenticated, None otherwise

**User Dictionary:**
```python
{
    'email': 'user@example.com',
    'name': 'John Doe',
    'picture': 'https://...',
}
```

**Example:**
```python
from flask_google_groups_auth.auth import get_current_user

user = get_current_user()
if user:
    print(f"Logged in as: {user['email']}")
```

### `login_user(user_info)`

Log in a user by storing their information in the session.

**Parameters:**
- `user_info` (dict): Dictionary with user information:
  - `email` (str): User's email address
  - `name` (str): User's display name
  - `picture` (str): URL to user's profile picture

**Side Effects:**
- Stores user info in session
- Sets session as permanent (uses `PERMANENT_SESSION_LIFETIME`)

**Example:**
```python
from flask_google_groups_auth.auth import login_user

user_info = {
    'email': 'user@example.com',
    'name': 'John Doe',
    'picture': 'https://...'
}
login_user(user_info)
```

### `logout_user()`

Log out the current user by clearing the session.

**Side Effects:**
- Clears entire session (including OAuth state and group membership cache)

**Example:**
```python
from flask_google_groups_auth.auth import logout_user

logout_user()
```

## Group Check Functions

### `is_group_member(user_email, group_emails)`

Check if a user is a member of any of the required groups. Uses server-side cache with TTL.

**Parameters:**
- `user_email` (str): Email address to check
- `group_emails` (str or list): Single group email or list of group emails

**Returns:**
- `bool`: True if user is a member of at least one group, False otherwise

**Cache Behavior:**
- Checks server-side cache first
- Cache TTL configured by `FLASK_GOOGLE_GROUPS_AUTH_CACHE_TTL` (default: 3600s)
- Falls back to session cache if API fails
- Returns False if all checks fail

**Example:**
```python
from flask_google_groups_auth.group_check import is_group_member

# Check single group
if is_group_member('user@example.com', 'admins@example.com'):
    print("User is an admin")

# Check multiple groups
groups = ['editors@example.com', 'viewers@example.com']
if is_group_member('user@example.com', groups):
    print("User has access")
```

### `clear_group_membership_cache(user_email=None)`

Clear all cached group membership status.

**Parameters:**
- `user_email` (str, optional): Email address to clear cache for. Uses current user if not provided.

**Side Effects:**
- Clears server-side cache entries
- Clears session cache entries
- Logs number of cleared entries

**Example:**
```python
from flask_google_groups_auth.group_check import clear_group_membership_cache

# Clear for specific user
clear_group_membership_cache('user@example.com')

# Clear for current user
clear_group_membership_cache()
```

### `check_group_membership(user_email, group_email)`

Low-level function to check if a user is a member of a specific Google Group. Makes actual API call.

**Parameters:**
- `user_email` (str): Email address of the user to check
- `group_email` (str): Email of the Google Group to check

**Returns:**
- `bool`: True if user is a member, False otherwise

**Raises:**
- Various exceptions for API errors (logged)

**Note:** Most users should use `is_group_member()` instead, which provides caching.

### `check_group_memberships(user_email, group_emails)`

Check if a user is a member of any of the specified Google Groups.

**Parameters:**
- `user_email` (str): Email address of the user to check
- `group_emails` (str or list): Single group email or list of group emails

**Returns:**
- `bool`: True if user is a member of at least one group, False otherwise

**Behavior:**
- Checks groups sequentially
- Returns True on first match (short-circuit)
- Continues checking even if one group check fails
- Logs access grants and denials

## Exceptions

### `OAuthStateError`

Raised when OAuth state parameter validation fails.

**Inherits:** `Exception`

**When Raised:**
- OAuth state parameter doesn't match session state
- Could indicate CSRF attack or expired OAuth flow

**Handled By:**
- `auth_callback` route (returns 400 error)

**Example:**
```python
from flask_google_groups_auth.auth import OAuthStateError

try:
    verify_oauth_callback(state, code)
except OAuthStateError as e:
    print(f"OAuth validation failed: {e}")
```

## Configuration Keys

### Environment Variables

**OAuth Configuration:**
- `GOOGLE_CLIENT_ID`: OAuth 2.0 client ID (direct value)
- `GOOGLE_CLIENT_SECRET`: OAuth 2.0 client secret (direct value)
- `REDIRECT_URI`: OAuth redirect URI (default: `/auth/callback`)

**Service Account:**
- `DELEGATED_ADMIN_EMAIL`: Admin email for domain-wide delegation (direct value)
- `GOOGLE_APPLICATION_CREDENTIALS`: Path to service account key file

**Secret Manager (Optional):**
- `GCP_PROJECT_ID`: Google Cloud project ID
- `DELEGATED_ADMIN_EMAIL_SECRET_NAME`: Secret name containing delegated admin email
- `GOOGLE_CLIENT_ID_SECRET_NAME`: Secret name containing OAuth client ID
- `GOOGLE_CLIENT_SECRET_SECRET_NAME`: Secret name containing OAuth client secret

### Flask App Config Keys

All keys use the `FLASK_GOOGLE_GROUPS_AUTH_` prefix:

**Core Configuration:**
- `FLASK_GOOGLE_GROUPS_AUTH_PROJECT_ID`: GCP project ID
- `FLASK_GOOGLE_GROUPS_AUTH_REDIRECT_URI`: OAuth redirect URI
- `FLASK_GOOGLE_GROUPS_AUTH_CACHE_TTL`: Cache TTL in seconds (default: 3600)

**Secret Manager (if used):**
- `FLASK_GOOGLE_GROUPS_AUTH_DELEGATED_ADMIN_EMAIL_SECRET_NAME`: Admin email secret name
- `FLASK_GOOGLE_GROUPS_AUTH_CLIENT_ID_SECRET_NAME`: Client ID secret name
- `FLASK_GOOGLE_GROUPS_AUTH_CLIENT_SECRET_SECRET_NAME`: Client secret secret name

**Direct Values (fallback):**
- `FLASK_GOOGLE_GROUPS_AUTH_ADMIN_EMAIL_ENV`: Direct admin email
- `FLASK_GOOGLE_GROUPS_AUTH_CLIENT_ID_ENV`: Direct client ID
- `FLASK_GOOGLE_GROUPS_AUTH_CLIENT_SECRET_ENV`: Direct client secret

**Session Security (auto-configured):**
- `SESSION_COOKIE_SECURE`: HTTPS only (default: True in production)
- `SESSION_COOKIE_HTTPONLY`: Prevent JavaScript access (default: True)
- `SESSION_COOKIE_SAMESITE`: CSRF protection (default: 'Lax')
- `PERMANENT_SESSION_LIFETIME`: Session timeout in seconds (default: 86400)

### Custom Configuration Example

```python
import os

app = Flask(__name__)

# Set Flask secret key (required for sessions)
app.secret_key = os.getenv('SECRET_KEY')  # or generate your own

# Optional overrides
app.config['FLASK_GOOGLE_GROUPS_AUTH_CACHE_TTL'] = 1800  # 30 minutes
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # More restrictive
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

config = Config(app)
```
