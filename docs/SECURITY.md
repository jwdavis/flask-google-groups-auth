# Security Configuration Guide

This guide covers security best practices and configuration for the `flask-google-groups-auth` package.

## Table of Contents

- [Session Security](#session-security)
- [OAuth Configuration](#oauth-configuration)
- [Credential Management](#credential-management)
- [Cache Security](#cache-security)
- [Network Security](#network-security)
- [Monitoring & Logging](#monitoring--logging)

## Session Security

### Required Configuration

The package automatically configures secure session cookies, but you **must** set `app.secret_key` in your application code:

```python
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Read from environment
# OR: app.secret_key = 'your-secret-key-here'  # Not recommended for production

config = Config(app)
```

**⚠️ WARNING**: Never hardcode the secret key in production. Use environment variables.

Generate a strong secret key:

```bash
python -c 'import secrets; print(secrets.token_hex(32))'
```

### Automatic Security Settings

The package automatically configures:

```python
SESSION_COOKIE_SECURE = True       # HTTPS only (disabled in debug mode)
SESSION_COOKIE_HTTPONLY = True     # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'    # CSRF protection
PERMANENT_SESSION_LIFETIME = 86400 # 24-hour timeout
```

### Custom Session Configuration

Override defaults if needed:

```python
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # More restrictive
app.config['PERMANENT_SESSION_LIFETIME'] = 3600   # 1 hour
```

## OAuth Configuration

### Redirect URI Security

**Always use HTTPS in production:**

```bash
# Development
export REDIRECT_URI=http://localhost:8080/auth/callback

# Production
export REDIRECT_URI=https://yourdomain.com/auth/callback
```

### Authorized Redirect URIs

In Google Cloud Console, configure **exact** redirect URIs:

1. Go to [APIs & Services > Credentials](https://console.cloud.google.com/apis/credentials)
2. Edit your OAuth 2.0 Client ID
3. Add authorized redirect URIs:
   - Development: `http://localhost:8080/auth/callback`
   - Production: `https://yourdomain.com/auth/callback`

**⚠️ Never** use wildcards or allow `http://` in production.

### OAuth State Protection

The package implements OAuth state parameter validation to prevent CSRF attacks:

- State is generated and stored in session
- Validated on callback
- Automatic cleanup on mismatch
- Logged as security events

## Credential Management

### Service Account Key Files

**Development:**
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
```

**Production (Cloud Run):**
- Use Application Default Credentials (ADC)
- Attach service account to Cloud Run service
- **Never** deploy key files with your application

**Best Practices:**
- Store key files outside version control
- Add to `.gitignore`:
  ```
  *.json
  service-account-*.json
  credentials.json
  ```
- Restrict file permissions: `chmod 600 service-account.json`
- Rotate keys regularly (every 90 days)

### Secret Manager (Recommended)

Use Google Secret Manager for production credentials:

```bash
# Store credentials
echo -n "admin@domain.com" | gcloud secrets create delegated-admin-email --data-file=-
echo -n "your-client-id" | gcloud secrets create google-client-id --data-file=-
echo -n "your-client-secret" | gcloud secrets create google-client-secret --data-file=-

# Grant access
gcloud secrets add-iam-policy-binding <secret-name> \
  --member="serviceAccount:sa@project.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

Configure application:
```bash
export GCP_PROJECT_ID=your-project-id
export DELEGATED_ADMIN_EMAIL_SECRET_NAME=delegated-admin-email
export GOOGLE_CLIENT_ID_SECRET_NAME=google-client-id
export GOOGLE_CLIENT_SECRET_SECRET_NAME=google-client-secret
```

### Environment Variables Priority

The package checks credentials in this order:

1. Secret Manager (if secret name provided)
2. Environment variable (direct value)
3. Raises error if neither found

## Cache Security

### Server-Side Cache

Group membership is cached server-side with TTL:

```python
# Default: 1 hour
app.config['FLASK_GOOGLE_GROUPS_AUTH_CACHE_TTL'] = 3600

# More restrictive: 15 minutes
app.config['FLASK_GOOGLE_GROUPS_AUTH_CACHE_TTL'] = 900

# Less restrictive: 4 hours (use with caution)
app.config['FLASK_GOOGLE_GROUPS_AUTH_CACHE_TTL'] = 14400
```

**Security Considerations:**
- Lower TTL = more API calls but fresher data
- Higher TTL = fewer API calls but delayed access revocation
- Balance based on your security requirements

### Cache Invalidation

Force cache refresh when group membership changes:

```python
from flask_google_groups_auth.group_check import clear_group_membership_cache

# Clear for specific user
clear_group_membership_cache('user@example.com')

# Clear for current user
clear_group_membership_cache()
```

**When to invalidate:**
- User role changes
- Group membership modified
- Security incident
- Regular maintenance

## Network Security

### HTTPS Enforcement

**Production:**
```python
# Force HTTPS redirects
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, force_https=True)
```

### Cloud Run Security

```bash
gcloud run deploy your-service \
  --platform managed \
  --ingress all \  # or 'internal-and-cloud-load-balancing' for private services
  --service-account your-sa@project.iam.gserviceaccount.com \
  --no-allow-unauthenticated  # Require Cloud Run authentication (optional)
```

### Firewall Rules

Restrict Admin Directory API access:

1. Use VPC Service Controls
2. Limit service account permissions
3. Enable audit logging

## Monitoring & Logging

### Security Events Logged

The package logs:

- OAuth state mismatches (possible CSRF)
- Group membership check failures
- Credential errors
- Cache operations

### Configure Logging Level

```python
import logging

# Production: WARNING or ERROR
logging.basicConfig(level=logging.WARNING)

# Development: DEBUG
logging.basicConfig(level=logging.DEBUG)
```

### Cloud Logging (Production)

```python
import google.cloud.logging

# Setup Cloud Logging
client = google.cloud.logging.Client()
client.setup_logging()
```

### Monitoring Checklist

- [ ] Monitor failed authentication attempts
- [ ] Alert on OAuth state mismatches
- [ ] Track API quota usage
- [ ] Monitor cache hit rates
- [ ] Review access logs regularly
- [ ] Set up uptime checks

## Security Checklist

### Development
- [ ] Use `.env` files (not committed)
- [ ] HTTP allowed for localhost only
- [ ] Debug mode enabled
- [ ] Use test Google Workspace

### Production
- [ ] `app.secret_key` set in application code
- [ ] HTTPS enforced everywhere
- [ ] Debug mode disabled (`app.debug = False`)
- [ ] Service account key **not** deployed
- [ ] Using Application Default Credentials or Secret Manager
- [ ] Session cookies configured (automatic)
- [ ] Redirect URIs restricted to production domain
- [ ] Cache TTL configured appropriately
- [ ] Logging configured to Cloud Logging
- [ ] Monitoring and alerts enabled

## Common Security Mistakes

### ❌ Don't Do This

```python
# Hardcoded secret key
app.secret_key = "mysecretkey123"

# Committing key files
git add service-account-key.json

# Using HTTP in production
REDIRECT_URI = "http://prod.example.com/auth/callback"

# Disabled security
app.config['SESSION_COOKIE_SECURE'] = False

# No TTL on cache
app.config['FLASK_GOOGLE_GROUPS_AUTH_CACHE_TTL'] = 86400 * 365  # 1 year!
```

### ✅ Do This

```python
# Environment-based configuration
app.secret_key = os.getenv('SECRET_KEY')

# Ignore key files
# .gitignore
*.json
.env

# HTTPS in production
REDIRECT_URI = "https://prod.example.com/auth/callback"

# Use defaults (automatically secure)
config = Config(app)

# Reasonable cache TTL
app.config['FLASK_GOOGLE_GROUPS_AUTH_CACHE_TTL'] = 3600  # 1 hour
```

## Incident Response

If you suspect a security breach:

1. **Immediately rotate credentials:**
   ```bash
   # Revoke and create new OAuth client
   # Rotate service account keys
   gcloud iam service-accounts keys create new-key.json --iam-account=sa@project.iam.gserviceaccount.com
   ```

2. **Clear all caches:**
   ```python
   # Clear server-side cache
   current_app.extensions['group_membership_cache'].clear()
   ```

3. **Review logs:**
   ```bash
   gcloud logging read "resource.type=cloud_run_revision" --limit 1000
   ```

4. **Update app.secret_key** (invalidates all sessions)

5. **Notify affected users**

## Security Contacts

Report security vulnerabilities to: jeff@roitraining.com

Do not publicly disclose security issues before they are addressed.
