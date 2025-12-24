"""
Google OAuth authentication for Flask applications.

Handles user authentication using Google OAuth 2.0.
"""

import os

from flask import current_app, redirect, request, session, url_for
from google.auth.transport import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow


class OAuthStateError(Exception):
    """Raised when OAuth state parameter validation fails.
    
    This could indicate a CSRF attack attempt or expired OAuth flow.
    """
    pass

def get_google_flow():
    """
    Create and return a Google OAuth flow.
    
    Returns:
        Flow: Configured Google OAuth flow
    """
    config = current_app.extensions['flask_google_groups_auth']
    oauth_config = config.get_oauth_config()
    
    client_config = {
        "web": {
            "client_id": oauth_config['client_id'],
            "client_secret": oauth_config['client_secret'],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [oauth_config['redirect_uri']],
        }
    }
    
    flow = Flow.from_client_config(
        client_config=client_config,
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
    )
    
    # Set redirect URI
    flow.redirect_uri = oauth_config['redirect_uri']
    
    return flow


def get_authorization_url():
    """
    Generate Google OAuth authorization URL.
    
    Returns:
        tuple: (authorization_url, state)
    """
    flow = get_google_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='select_account'
    )
    
    return authorization_url, state


def verify_oauth_callback(state, code):
    """
    Verify OAuth callback and exchange code for tokens.
    
    Args:
        state: OAuth state parameter
        code: Authorization code from Google
        
    Returns:
        dict: User information including email, name, and picture
        
    Raises:
        OAuthStateError: If state doesn't match or verification fails
    """
    if state != session.get('oauth_state'):
        current_app.logger.warning(
            f"OAuth state mismatch - possible CSRF attempt. "
            f"Expected: {session.get('oauth_state')}, Got: {state}, "
            f"IP: {request.remote_addr}"
        )
        # Clear stale OAuth state
        session.pop('oauth_state', None)
        raise OAuthStateError("Invalid authentication state - please try logging in again")
    
    flow = get_google_flow()
    flow.fetch_token(code=code)
    
    credentials = flow.credentials
    
    # Get user info from ID token
    id_info = id_token.verify_oauth2_token(
        credentials.id_token,
        requests.Request(),
        current_app.extensions['flask_google_groups_auth'].get_oauth_config()['client_id']
    )
    
    return {
        'email': id_info.get('email'),
        'name': id_info.get('name'),
        'picture': id_info.get('picture'),
        'email_verified': id_info.get('email_verified', False),
    }


def is_authenticated():
    """
    Check if user is authenticated.
    
    Returns:
        bool: True if user is authenticated, False otherwise
    """
    return 'user_email' in session and session.get('user_email') is not None


def get_current_user():
    """
    Get current authenticated user information.
    
    Returns:
        dict: User information or None if not authenticated
    """
    if not is_authenticated():
        return None
    
    return {
        'email': session.get('user_email'),
        'name': session.get('user_name'),
        'picture': session.get('user_picture'),
    }


def login_user(user_info):
    """
    Log in a user by storing their information in the session.
    
    Args:
        user_info: Dictionary with user information (email, name, picture)
    """
    session['user_email'] = user_info.get('email')
    session['user_name'] = user_info.get('name')
    session['user_picture'] = user_info.get('picture')
    session.permanent = True


def logout_user():
    """Log out the current user by clearing the session."""
    # Clear the entire session to ensure no stale OAuth state
    session.clear()


def setup_auth_routes(app):
    """
    Set up authentication routes for the Flask app.
    
    Args:
        app: Flask application instance
    """
    
    @app.route('/auth/login')
    def auth_login():
        """Initiate Google OAuth login."""
        authorization_url, state = get_authorization_url()
        session['oauth_state'] = state
        
        # Store the page user was trying to access
        session['next_url'] = request.args.get('next', '/')
        
        return redirect(authorization_url)
    
    @app.route('/auth/callback')
    def auth_callback():
        """Handle OAuth callback from Google."""
        state = request.args.get('state')
        code = request.args.get('code')
        error = request.args.get('error')
        
        if error:
            return f"Authentication error: {error}", 400
        
        try:
            user_info = verify_oauth_callback(state, code)
            
            if not user_info.get('email_verified'):
                return "Email not verified", 403
            
            login_user(user_info)
            
            # Redirect to the page user was trying to access
            next_url = session.pop('next_url', '/')
            return redirect(next_url)
            
        except OAuthStateError as e:
            # OAuth state validation failed - likely CSRF or expired flow
            return f"Authentication failed: {str(e)}", 400
        except Exception as e:
            current_app.logger.error(f"Authentication error: {e}")
            return f"Authentication failed: {str(e)}", 500
    
    @app.route('/auth/logout')
    def auth_logout():
        """Log out the current user."""
        logout_user()
        return redirect('/')
