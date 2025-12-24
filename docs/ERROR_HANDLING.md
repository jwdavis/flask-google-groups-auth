# Error Handling Guide

Guide to understanding and handling errors in `flask-google-groups-auth`.

## Table of Contents

- [Common Errors](#common-errors)
- [Configuration Errors](#configuration-errors)
- [Authentication Errors](#authentication-errors)
- [Group Check Errors](#group-check-errors)
- [Custom Error Handlers](#custom-error-handlers)

## Common Errors

### "No SECRET_KEY configured"

**Symptom:**
```
WARNING: No SECRET_KEY configured. Auto-generating one, but this will 
invalidate sessions on restart. Set SECRET_KEY environment variable in production.
```

**Cause:** Flask `app.secret_key` not set in your application code

**Solution:**

Set `app.secret_key` in your Flask application before initializing the auth module:

```python
import os
import secrets

app = Flask(__name__)

# Option 1: Read from environment variable (recommended)
app.secret_key = os.getenv('SECRET_KEY')

# Option 2: Generate during app initialization (dev only)
if app.debug:
    app.secret_key = secrets.token_hex(32)
```

Generate a strong secret key:
```bash
python -c 'import secrets; print(secrets.token_hex(32))'
```

---

### "GCP project ID not configured"

**Full Error:**
```
ValueError: GCP project ID not configured
```

**Cause:** Trying to use Secret Manager without setting project ID

**Solution:**
```bash
export GCP_PROJECT_ID=your-project-id
```

**Or** don't use Secret Manager (use direct env vars instead):
```bash
export DELEGATED_ADMIN_EMAIL=admin@yourdomain.com
export GOOGLE_CLIENT_ID=your-client-id
export GOOGLE_CLIENT_SECRET=your-client-secret
```

---

### "GOOGLE_APPLICATION_CREDENTIALS environment variable not set"

**Full Error:**
```
ValueError: GOOGLE_APPLICATION_CREDENTIALS environment variable not set.
This is required when not using Application Default Credentials.
```

**Cause:** Running locally without specifying service account key file

**Solution (Development):**
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
```

**Solution (Cloud Run - Recommended):**
Deploy with service account attached - no key file needed:
```bash
gcloud run deploy your-service \
  --service-account your-sa@project.iam.gserviceaccount.com
```

---

## Configuration Errors

### "Delegated admin email not configured"

**Full Error:**
```
ValueError: Delegated admin email not configured. 
Set DELEGATED_ADMIN_EMAIL_SECRET_NAME (for Secret Manager) or DELEGATED_ADMIN_EMAIL (env var)
```

**Cause:** Neither Secret Manager secret nor environment variable is set for admin email

**Solution (Option 1 - Direct env var):**
```bash
export DELEGATED_ADMIN_EMAIL=admin@yourdomain.com
```

**Solution (Option 2 - Secret Manager):**
```bash
# Create secret
echo -n "admin@yourdomain.com" | \
  gcloud secrets create delegated-admin-email --data-file=-

# Configure app
export GCP_PROJECT_ID=your-project-id
export DELEGATED_ADMIN_EMAIL_SECRET_NAME=delegated-admin-email
```

---

### "Google OAuth client ID not configured"

**Full Error:**
```
ValueError: Google OAuth client ID not configured.
Set GOOGLE_CLIENT_ID_SECRET_NAME (for Secret Manager) or GOOGLE_CLIENT_ID (env var)
```

**Solution:**
```bash
export GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
```

---

### "Google OAuth client secret not configured"

**Full Error:**
```
ValueError: Google OAuth client secret not configured.
Set GOOGLE_CLIENT_SECRET_SECRET_NAME (for Secret Manager) or GOOGLE_CLIENT_SECRET (env var)
```

**Solution:**
```bash
export GOOGLE_CLIENT_SECRET=your-client-secret
```

---

## Authentication Errors

### "Invalid authentication state - please try logging in again"

**HTTP Status:** 400 Bad Request

**Cause:** OAuth state parameter doesn't match (possible causes):
- User clicked old/stale login link
- Session expired during OAuth flow
- Possible CSRF attack attempt
- Browser privacy features blocking cookies

**Solution for Users:**
- Clear browser cookies
- Try logging in again
- Ensure cookies are enabled

**Solution for Developers:**
- Check session configuration
- Verify `app.secret_key` is set and persistent
- Review security logs for patterns

---

### "Email not verified"

**HTTP Status:** 403 Forbidden

**Cause:** User's Google account email is not verified

**Solution for Users:**
- Verify email in Google account settings
- Check spam folder for verification email

---

### "Authentication error: [Google error]"

**HTTP Status:** 400 Bad Request

**Cause:** Google OAuth returned an error (user cancelled, app not approved, etc.)

**Common Google Errors:**
- `access_denied`: User cancelled login
- `redirect_uri_mismatch`: Redirect URI not configured in Google Console

**Solution:**
- For redirect URI mismatch: Add exact redirect URI to Google Cloud Console
- For access_denied: User needs to approve the app

---

## Group Check Errors

### "User is not a member of required groups"

**HTTP Status:** 403 Forbidden

**Logged as:**
```
WARNING: User user@example.com attempted to access /admin but is not a 
member of required groups: ['admins@example.com']
```

**Cause:** User authenticated successfully but not in required Google Group

**Solution for Admins:**
1. Add user to appropriate Google Group in Google Workspace Admin Console
2. Wait for sync (usually immediate)
3. Clear cache: `clear_group_membership_cache('user@example.com')`
4. Ask user to try again

**Solution for Users:**
- Contact your administrator
- Verify your email address

---

### "Failed to check group membership"

**Logged as:**
```
ERROR: Failed to check group membership: [error details]
```

**Common Causes & Solutions:**

**1. Domain-wide delegation not configured:**
```
Error: Not Authorized to access this resource/api
```
**Solution:** Configure domain-wide delegation in Google Workspace Admin:
- Go to Security > API Controls > Domain-wide Delegation
- Add service account's Client ID
- Scope: `https://www.googleapis.com/auth/admin.directory.group.member.readonly`

**2. Service account lacks permissions:**
```
Error: Request had insufficient authentication scopes
```
**Solution:** Verify scope in domain-wide delegation config

**3. Group doesn't exist:**
```
Error: Resource Not Found
```
**Solution:** Verify group email is correct

**4. Admin email lacks permissions:**
```
Error: Not Authorized
```
**Solution:** Delegated admin email must have permissions to view groups

**5. API not enabled:**
```
Error: Admin SDK API has not been used
```
**Solution:**
```bash
gcloud services enable admin.googleapis.com --project=your-project-id
```

---

## Custom Error Handlers

### Basic Error Handling

```python
from flask import render_template
from flask_google_groups_auth.auth import OAuthStateError

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 errors (not in required group)"""
    return render_template('403.html'), 403

@app.errorhandler(OAuthStateError)
def handle_oauth_state_error(error):
    """Handle OAuth state validation errors"""
    return render_template('oauth_error.html', error=error), 400
```

### Advanced Error Handling

```python
from flask import jsonify, request
import logging

logger = logging.getLogger(__name__)

@app.errorhandler(403)
def forbidden(error):
    """Custom 403 handler with JSON support"""
    # Log the attempt
    user = get_current_user()
    logger.warning(
        f"403 Forbidden: {user.get('email') if user else 'Unknown'} "
        f"attempted to access {request.path}"
    )
    
    # Return JSON for API requests
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Forbidden',
            'message': 'You do not have permission to access this resource'
        }), 403
    
    # Return HTML for web requests
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors with logging"""
    logger.error(f"Internal server error: {error}", exc_info=True)
    return render_template('errors/500.html'), 500
```

### Retry Logic for Group Checks

```python
from flask_google_groups_auth.group_check import is_group_member
import time

def is_group_member_with_retry(user_email, groups, max_retries=3):
    """Check group membership with retry logic"""
    for attempt in range(max_retries):
        try:
            return is_group_member(user_email, groups)
        except Exception as e:
            if attempt == max_retries - 1:
                # Last attempt failed
                logger.error(f"Group check failed after {max_retries} attempts: {e}")
                return False
            
            # Wait before retry (exponential backoff)
            wait_time = 2 ** attempt
            logger.warning(f"Group check failed, retrying in {wait_time}s: {e}")
            time.sleep(wait_time)
    
    return False
```

### Graceful Degradation

```python
from flask_google_groups_auth.decorators import require_auth
from flask_google_groups_auth.group_check import is_group_member

@app.route('/content')
@require_auth
def content():
    """Route with graceful degradation for group checks"""
    user = get_current_user()
    
    try:
        is_editor = is_group_member(user['email'], 'editors@example.com')
    except Exception as e:
        logger.error(f"Failed to check editor status: {e}")
        is_editor = False  # Fail closed
    
    # Show limited content if group check fails
    if is_editor:
        return render_template('content_full.html')
    else:
        return render_template('content_limited.html')
```

## Debugging Tips

### Enable Debug Logging

```python
import logging

# Set logging level
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)

# Or for specific module
logger = logging.getLogger('flask_google_groups_auth')
logger.setLevel(logging.DEBUG)
```

### Check Current User State

```python
@app.route('/debug/user')
def debug_user():
    """Debug endpoint to check user state"""
    if not app.debug:
        return "Only available in debug mode", 403
    
    user = get_current_user()
    return jsonify({
        'authenticated': is_authenticated(),
        'user': user,
        'session_keys': list(session.keys()),
    })
```

### Test Group Membership

```python
@app.route('/debug/groups')
@require_auth
def debug_groups():
    """Debug endpoint to check group membership"""
    if not app.debug:
        return "Only available in debug mode", 403
    
    user = get_current_user()
    test_groups = ['admins@example.com', 'editors@example.com']
    
    results = {}
    for group in test_groups:
        try:
            results[group] = is_group_member(user['email'], group)
        except Exception as e:
            results[group] = f"Error: {str(e)}"
    
    return jsonify(results)
```

## Getting Help

If you encounter an error not covered here:

1. **Check logs** for detailed error messages
2. **Enable debug logging** to see more details
3. **Review configuration** - most errors are configuration-related
4. **Check Google Cloud Console** for API quota and errors
5. **File an issue** at https://github.com/jwdavis/flask-google-groups-auth/issues

When filing an issue, include:
- Error message and stack trace
- Relevant configuration (redact secrets!)
- Steps to reproduce
- Environment (local, Cloud Run, etc.)
