# Flask Google Groups Auth

This Flask extension provides OAuth-based authentication with Google and verifies user membership in Google Groups. It allows you to protect Flask routes by requiring users to authenticate with their Google account and optionally requiring them to be members of specific Google Groups.

The package uses Google's OAuth 2.0 for user login and leverages service account domain-wide delegation to check Google Group memberships. This means you can restrict access to certain parts of your application based on which Google Groups users belong to—useful for implementing role-based access control when your organization uses Google Workspace.

Configuration can be managed through environment variables or Google Cloud Secret Manager. Session caching is included to minimize API calls and improve performance.

## Quick Start

### Installation

Add this package as a dependency in your application's `requirements.txt` file:

```
git+https://github.com/jwdavis/flask-google-groups-auth.git
```

Then install your application's dependencies:

```bash
pip install -r requirements.txt
```

### Configuration

1. **Configure domain-wide delegation:**
   - Go to [Google Workspace Admin Console](https://admin.google.com)
   - Navigate to Security > API Controls > Domain-wide Delegation
   - Add your service account's Client ID with scope:
     - `https://www.googleapis.com/auth/admin.directory.group.member.readonly`

2. **Create OAuth credentials:**
   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Navigate to APIs & Services > Credentials
   - Create OAuth 2.0 Client ID (Web application)
   - Add authorized redirect URIs:
     - For local development: `http://localhost:8080/auth/callback`
     - For Cloud Run: `https://your-service-url.run.app/auth/callback`

3. **Provide configuration values:**

    The package requires the following configuration:
    - **Delegated admin email**: A Google Workspace admin email that the service account will impersonate
    - **OAuth client ID**: From step 2
    - **OAuth client secret**: From step 2
    - **Redirect URI**: Must match one configured in step 2

    You have two options for providing these values:

    **Option A: Environment Variables (simpler, good for development)**
    
    Set the values directly as environment variables or in a `.env` file. This is the simplest approach for local development.

    **Option B: Google Secret Manager (recommended for production)**
    
    Store sensitive values in Secret Manager and provide the secret names via environment variables. This is more secure for production deployments and avoids exposing credentials in your environment.

4. **Set up configuration based on your chosen approach:**

    **Option A: Using direct environment variables**
    
    Set these environment variables (or add to a `.env` file):
    ```bash
    # Required: OAuth credentials (actual values)
    GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
    GOOGLE_CLIENT_SECRET=your-client-secret
    
    # Required: Delegated admin email (actual email address)
    DELEGATED_ADMIN_EMAIL=admin@yourdomain.com
    
    # Required: OAuth redirect URI
    REDIRECT_URI=http://localhost:8080/auth/callback
    
    # Required for local development: Service account key
    GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
    ```

    **Option B: Using Google Secret Manager**
    
    First, create secrets in Secret Manager for each sensitive value:
    ```bash
    # Create secret for delegated admin email
    echo -n "admin@yourdomain.com" | \
      gcloud secrets create delegated-admin-email --data-file=-
    
    # Create secret for OAuth client ID
    echo -n "your-client-id.apps.googleusercontent.com" | \
      gcloud secrets create google-oauth-client-id --data-file=-
    
    # Create secret for OAuth client secret
    echo -n "your-client-secret" | \
      gcloud secrets create google-oauth-client-secret --data-file=-
    
    # Grant service account access to all secrets
    for secret in delegated-admin-email google-oauth-client-id google-oauth-client-secret; do
      gcloud secrets add-iam-policy-binding $secret \
        --member="serviceAccount:your-sa@project.iam.gserviceaccount.com" \
        --role="roles/secretmanager.secretAccessor"
    done
    ```
    
    Then set these environment variables with the **names** of the secrets:
    ```bash
    # Required: GCP project ID where secrets are stored
    GCP_PROJECT_ID=your-project-id
    
    # Required: Names of secrets in Secret Manager (not the actual values)
    DELEGATED_ADMIN_EMAIL_SECRET_NAME=delegated-admin-email
    GOOGLE_CLIENT_ID_SECRET_NAME=google-oauth-client-id
    GOOGLE_CLIENT_SECRET_SECRET_NAME=google-oauth-client-secret
    
    # Required: OAuth redirect URI
    REDIRECT_URI=http://localhost:8080/auth/callback
    
    # Required for local development: Service account key
    # (Not needed on Cloud Run where service account is automatic)
    GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
    ```

    An example `.env` file is provided in this repository showing both approaches.

## Usage

### Basic Example

```python
from flask import Flask
from flask_google_groups_auth import Config, require_auth, require_group_member
from flask_google_groups_auth.auth import setup_auth_routes, get_current_user

app = Flask(__name__)
config = Config(app)
setup_auth_routes(app)

# Public route
@app.route('/')
def home():
    user = get_current_user()
    return f"Hello {'guest' if not user else user['name']}"

# Requires authentication
@app.route('/dashboard')
@require_auth
def dashboard():
    user = get_current_user()
    return f"Welcome, {user['name']}!"

# Requires authentication AND group membership
@app.route('/admin')
@require_group_member('admins@yourdomain.com')
def admin():
    return "Admin panel"

# Multiple groups (OR logic - user must be in at least one)
@app.route('/content')
@require_group_member(['editors@yourdomain.com', 'admins@yourdomain.com'])
def content():
    return "Content area"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
```

### Decorators

**`@require_auth`** - Requires authentication, redirects to login if not authenticated

**`@require_group_member(groups)`** - Requires authentication AND group membership
- `groups`: Single group email (string) or list of group emails
- User must be in at least one group (OR logic)
- Returns 403 if user is not a member

### Helper Functions

```python
from flask_google_groups_auth.auth import get_current_user, is_authenticated, logout_user
from flask_google_groups_auth.group_check import is_group_member, clear_group_membership_cache

# Check authentication
if is_authenticated():
    user = get_current_user()  # Returns dict with email, name, picture

# Check group membership
if is_group_member('user@example.com', 'admins@yourdomain.com'):
    print("User is an admin")

# Check multiple groups
if is_group_member('user@example.com', ['group1@domain.com', 'group2@domain.com']):
    print("User is in at least one group")

# Clear cache
clear_group_membership_cache()
```

## Local Development

```bash
# Run setup script
./setup-dev.sh

# Activate virtual environment
source .venv/bin/activate

# Run example
python examples/multi_group_example.py
```

Visit `http://localhost:8080`

## Cloud Run Deployment

```bash
# Deploy
gcloud run deploy auth-group-demo \
    --source . \
    --platform managed \
    --region us-central1 \
    --allow-unauthenticated \
    --service-account your-sa@project.iam.gserviceaccount.com \
    --set-env-vars "GCP_PROJECT_ID=your-project-id" \
    --set-env-vars "GOOGLE_CLIENT_ID=your-client-id" \
    --set-env-vars "GOOGLE_CLIENT_SECRET=your-client-secret" \
    --set-env-vars "DELEGATED_ADMIN_EMAIL_SECRET_NAME=delegated-admin-email" \
    --set-env-vars "REDIRECT_URI=https://your-app-url.run.app/auth/callback"
```

Don't forget to add the Cloud Run URL to your OAuth redirect URIs!

## Module Structure

```
flask_google_groups_auth/
├── __init__.py       # Module exports
├── config.py         # Configuration and Secret Manager
├── auth.py           # Google OAuth authentication
├── group_check.py    # Group membership checking
└── decorators.py     # Flask decorators

examples/
├── multi_group_example.py      # Multiple group examples
└── integration_example.py      # Integration examples
```

## Documentation

- **[Security Configuration Guide](docs/SECURITY.md)** - Production security, credential management, session configuration, and best practices
- **[API Reference](docs/API.md)** - Complete function reference with parameters, return values, and examples
- **[Error Handling Guide](docs/ERROR_HANDLING.md)** - Troubleshooting common errors and custom error handlers

## Security Best Practices

- Never commit `.env` files or service account keys
- Use HTTPS in production
- Rotate secrets regularly
- Use strong session keys
- Implement rate limiting
- Monitor API usage
- Review service account permissions

## Troubleshooting

**"Email not verified"** - Google account needs verified email

**"Authentication failed"** - Check OAuth credentials and redirect URI

**"Error checking group membership"**
- Verify domain-wide delegation is configured
- Check service account has correct scope
- Ensure delegated admin email has group permissions
- Verify Google Group exists

**"GCP project ID not configured"** - Set `GCP_PROJECT_ID` environment variable

## License

MIT License - See LICENSE file for details
