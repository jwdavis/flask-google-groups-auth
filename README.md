# Flask Google Groups Auth

**Version 0.3.0** - Flask extension for Google OAuth authentication with Google Groups membership verification

A simplified authentication solution for Flask applications that need to:
- Authenticate users via Google OAuth 2.0
- Verify Google Group memberships using service account domain-wide delegation
- Protect routes based on authentication and group membership
- Deploy seamlessly to both local development and Google Cloud Run

## Quick Start

### Installation

```bash
# Add to requirements.txt
git+https://github.com/jwdavis/flask-google-groups-auth.git

# Install
pip install -r requirements.txt
```

### Basic Usage

```python
from flask import Flask
from flask_google_groups_auth import Config, require_auth, require_group_member
from flask_google_groups_auth.auth import setup_auth_routes, get_current_user

app = Flask(__name__)
Config(app)
setup_auth_routes(app)

@app.route('/')
def home():
    user = get_current_user()
    return f"Hello {user['name'] if user else 'guest'}"

@app.route('/dashboard')
@require_auth
def dashboard():
    return "Protected content"

@app.route('/admin')
@require_group_member('admins@yourdomain.com')
def admin():
    return "Admin panel"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

## Setup Guide

### Prerequisites

**1. Create Service Account with Domain-Wide Delegation**

In [Google Cloud Console](https://console.cloud.google.com):
- Navigate to IAM & Admin > Service Accounts
- Create new service account
- Download JSON key file (for local dev and Secret Manager)
- Note the Client ID

In [Google Workspace Admin Console](https://admin.google.com):
- Navigate to Security > API Controls > Domain-wide Delegation
- Add service account Client ID with scope: `https://www.googleapis.com/auth/admin.directory.group.member.readonly`

**2. Create OAuth 2.0 Credentials**

In [Google Cloud Console](https://console.cloud.google.com):
- Navigate to APIs & Services > Credentials
- Create OAuth 2.0 Client ID (Web application)
- Add authorized redirect URIs:
  - Local: `http://localhost:8080/auth/callback`
  - Cloud Run: `https://your-service.run.app/auth/callback`

### Local Development

Create `.env` file:

```bash
SERVICE_ACCOUNT_KEY_FILE=/path/to/service-account-key.json
DELEGATED_ADMIN_EMAIL=admin@yourdomain.com
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxx
REDIRECT_URI=http://localhost:8080/auth/callback
SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
```

Run application:

```bash
python app.py
```

### Cloud Run Deployment

**1. Store service account key in Secret Manager:**

```bash
gcloud secrets create service-account-key \
  --data-file=/path/to/service-account-key.json

gcloud secrets add-iam-policy-binding service-account-key \
  --member="serviceAccount:cloudrun-sa@project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

**2. Deploy to Cloud Run:**

```bash
gcloud run deploy your-service \
  --source . \
  --service-account cloudrun-sa@project.iam.gserviceaccount.com \
  --set-env-vars "\
GCP_PROJECT_ID=your-project-id,\
SERVICE_ACCOUNT_KEY_SECRET=service-account-key,\
DELEGATED_ADMIN_EMAIL=admin@yourdomain.com,\
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com,\
GOOGLE_CLIENT_SECRET=GOCSPX-xxx,\
REDIRECT_URI=https://your-service.run.app/auth/callback,\
SECRET_KEY=your-secret-key"
```

**3. Update OAuth redirect URIs in Google Cloud Console to include your Cloud Run URL**

## Configuration Reference

### Environment Variables

| Variable | Local | Cloud Run | Description |
|----------|:-----:|:---------:|-------------|
| `SERVICE_ACCOUNT_KEY_FILE` | ✅ | ❌ | Path to service account JSON key file |
| `GCP_PROJECT_ID` | ❌ | ✅ | GCP project ID for Secret Manager |
| `SERVICE_ACCOUNT_KEY_SECRET` | ❌ | ✅ | Secret Manager secret name |
| `DELEGATED_ADMIN_EMAIL` | ✅ | ✅ | Google Workspace admin email |
| `GOOGLE_CLIENT_ID` | ✅ | ✅ | OAuth 2.0 client ID |
| `GOOGLE_CLIENT_SECRET` | ✅ | ✅ | OAuth 2.0 client secret |
| `REDIRECT_URI` | ✅ | ✅ | OAuth callback URL |
| `SECRET_KEY` | ✅ | ✅ | Flask session secret key |

### Decorators

**`@require_auth`**
- Requires user authentication
- Redirects to Google login if not authenticated

**`@require_group_member(groups)`**
- Requires authentication AND group membership
- `groups`: String (single group) or list (multiple groups with OR logic)
- Returns 403 if user is not in any specified group

```python
# Single group
@require_group_member('admins@yourdomain.com')

# Multiple groups (user must be in at least one)
@require_group_member(['editors@yourdomain.com', 'admins@yourdomain.com'])
```

### Helper Functions

```python
from flask_google_groups_auth.auth import get_current_user, is_authenticated
from flask_google_groups_auth.group_check import is_group_member

# Check authentication
if is_authenticated():
    user = get_current_user()  # Returns: {'email': '...', 'name': '...', 'picture': '...'}

# Check group membership
if is_group_member('user@example.com', 'admins@yourdomain.com'):
    print("User is admin")

# Check multiple groups (OR logic)
if is_group_member('user@example.com', ['group1@domain.com', 'group2@domain.com']):
    print("User is in at least one group")
```