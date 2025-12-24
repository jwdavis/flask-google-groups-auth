"""
Flask decorators for protecting routes with authentication and group membership checks.
"""

from functools import wraps

from flask import abort, current_app, redirect, request, url_for

from .auth import get_current_user, is_authenticated
from .group_check import is_group_member


def require_auth(f):
    """
    Decorator that requires a user to be authenticated.
    
    If the user is not authenticated, redirects to the login page.
    After successful login, the user will be redirected back to the original page.
    
    Usage:
        @app.route('/protected')
        @require_auth
        def protected_route():
            return "This is protected"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            # Store the current URL to redirect back after login
            return redirect(url_for('auth_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def require_group_member(groups):
    """
    Decorator that requires a user to be authenticated AND a member of at least one of the specified Google Groups.
    
    If the user is not authenticated, redirects to the login page.
    If the user is authenticated but not a group member, returns a 403 Forbidden error.
    
    Args:
        groups: A single group email (string) or a list of group emails.
                The user must be a member of at least one group (OR logic).
    
    Usage:
        # Single group
        @app.route('/admin')
        @require_group_member('admins@example.com')
        def admin_route():
            return "This requires admin group membership"
        
        # Multiple groups (user needs to be in at least one)
        @app.route('/content')
        @require_group_member(['editors@example.com', 'admins@example.com'])
        def content_route():
            return "This requires editor or admin group membership"
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not is_authenticated():
                # Store the current URL to redirect back after login
                return redirect(url_for('auth_login', next=request.url))
            
            # Check group membership
            user = get_current_user()
            if not is_group_member(user['email'], groups):
                current_app.logger.warning(f"User {user['email']} attempted to access {request.path} but is not a member of required groups: {groups}")
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def optional_auth(f):
    """
    Decorator that makes authentication optional but provides user info if authenticated.
    
    The decorated function can access user information if available, but doesn't require it.
    User info is available via get_current_user().
    
    Usage:
        @app.route('/optional')
        @optional_auth
        def optional_route():
            user = get_current_user()
            if user:
                return f"Hello {user['name']}"
            return "Hello guest"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Just pass through - user can check authentication status inside the function
        return f(*args, **kwargs)
    return decorated_function
