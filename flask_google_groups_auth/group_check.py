"""
Google Group membership checking using domain-wide delegation.

Uses service account key file with domain-wide delegation (DWD).
For local: reads key file from filesystem
For Cloud Run: reads key file JSON from Secret Manager
"""

import hashlib
from datetime import datetime

from flask import current_app, session
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


def get_admin_directory_service():
    """
    Create Admin Directory API service with domain-wide delegation.
    
    Uses service account credentials from key file (local) or Secret Manager (Cloud Run).
    The service account must have domain-wide delegation enabled with scope:
        https://www.googleapis.com/auth/admin.directory.group.member.readonly
    
    Returns:
        Resource: Admin Directory API service
        
    Raises:
        ValueError: If required credentials are not available
    """
    config = current_app.extensions['flask_google_groups_auth']
    delegated_admin_email = config.get_delegated_admin_email()
    service_account_info = config.get_service_account_info()
    scopes = ['https://www.googleapis.com/auth/admin.directory.group.member.readonly']
    
    try:
        current_app.logger.debug(f"Creating credentials with delegated admin: {delegated_admin_email}")
        
        # Create credentials from service account info (dict)
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=scopes,
            subject=delegated_admin_email
        )
        
        # Build and return the Admin Directory service
        return build('admin', 'directory_v1', credentials=credentials)
        
    except Exception as e:
        error_msg = (
            f"Failed to create Admin Directory service: {e}\n"
            f"Delegated admin: {delegated_admin_email}"
        )
        current_app.logger.error(error_msg)
        raise


def check_group_membership(user_email, group_email):
    """
    Check if a user is a member of a specific Google Group.
    
    Args:
        user_email: Email address of the user to check
        group_email: Email of the Google Group to check
        
    Returns:
        bool: True if user is a member, False otherwise
    """
    try:
        # Get Admin Directory service
        service = get_admin_directory_service()
        
        # Check if the user is a member of the group
        try:
            member = service.members().get(
                groupKey=group_email,
                memberKey=user_email
            ).execute()
            
            # If we get here, the user is a member
            current_app.logger.info(f"User {user_email} is a member of {group_email}")
            return True
            
        except HttpError as e:
            if e.resp.status == 404:
                # User is not a member
                current_app.logger.info(f"User {user_email} is not a member of {group_email}")
                return False
            else:
                # Some other error occurred
                current_app.logger.error(f"Error checking group membership: {e}")
                raise
    
    except Exception as e:
        current_app.logger.error(f"Error checking group membership: {e}")
        raise


def check_group_memberships(user_email, group_emails):
    """
    Check if a user is a member of any of the specified Google Groups.
    
    Args:
        user_email: Email address of the user to check
        group_emails: Single group email (string) or list of group emails to check
        
    Returns:
        bool: True if user is a member of at least one group, False otherwise
    """
    if not group_emails:
        raise ValueError("group_emails parameter is required")
    
    # Ensure group_emails is a list
    if isinstance(group_emails, str):
        group_emails = [group_emails]
    
    # Check each group - return True if user is in ANY group
    for group_email in group_emails:
        try:
            if check_group_membership(user_email, group_email):
                current_app.logger.info(f"User {user_email} granted access via group {group_email}")
                return True
        except Exception as e:
            current_app.logger.error(f"Error checking membership in {group_email}: {e}")
            # Continue checking other groups even if one fails
            continue
    
    current_app.logger.info(f"User {user_email} is not a member of any required groups: {group_emails}")
    return False


def is_group_member(user_email, group_emails):
    """
    Check if the specified user is a member of any of the required groups.
    
    Uses server-side cache with TTL to avoid repeated API calls.
    Falls back to session cache if server cache is unavailable.
    
    Args:
        user_email: Email address to check
        group_emails: Single group email (string) or list of group emails to check
        
    Returns:
        bool: True if user is a member of at least one group, False otherwise
    """
    if not user_email:
        return False
    
    if not group_emails:
        raise ValueError("group_emails parameter is required")
    
    # Ensure group_emails is a list
    if isinstance(group_emails, str):
        group_emails = [group_emails]
    
    # Create cache key using hash for security and consistency
    groups_str = ','.join(sorted(group_emails))
    cache_key = hashlib.sha256(f"{user_email}:{groups_str}".encode()).hexdigest()
    
    # Check server-side cache first
    cache = current_app.extensions.get('group_membership_cache', {})
    ttl = current_app.config.get('FLASK_GOOGLE_GROUPS_AUTH_CACHE_TTL', 3600)
    
    if cache_key in cache:
        cached_result, cached_time = cache[cache_key]
        age = (datetime.now() - cached_time).total_seconds()
        if age < ttl:
            current_app.logger.debug(
                f"Cache hit for {user_email} (age: {age:.0f}s, TTL: {ttl}s)"
            )
            return cached_result
        else:
            current_app.logger.debug(f"Cache expired for {user_email} (age: {age:.0f}s)")
    
    # Check group membership via API
    try:
        is_member = check_group_memberships(user_email, group_emails)
        
        # Store in server-side cache with timestamp
        cache[cache_key] = (is_member, datetime.now())
        
        # Also store in session as backup (for session-specific context)
        session[f'group_member_{cache_key}'] = is_member
        
        current_app.logger.debug(f"Cached group membership for {user_email}: {is_member}")
        return is_member
    
    except Exception as e:
        current_app.logger.error(f"Failed to check group membership: {e}")
        # Fall back to session cache if API call fails
        session_result = session.get(f'group_member_{cache_key}')
        if session_result is not None:
            current_app.logger.info(f"Using session cache fallback for {user_email}")
            return session_result
        return False


def clear_group_membership_cache(user_email=None):
    """
    Clear all cached group membership status for a user.
    
    This removes entries from both server-side cache and session cache.
    
    Args:
        user_email: Email address to clear cache for (uses current user if not provided)
    """
    if user_email is None:
        user_email = session.get('user_email')
    
    if not user_email:
        return
    
    cleared_count = 0
    
    # Clear server-side cache
    # Need to check all keys since they're hashed
    cache = current_app.extensions.get('group_membership_cache', {})
    keys_to_remove = []
    
    for cache_key, (_, _) in list(cache.items()):
        # We can't easily reverse the hash, so we clear all entries
        # In a production system, you might store email->keys mapping
        keys_to_remove.append(cache_key)
    
    for key in keys_to_remove:
        cache.pop(key, None)
        cleared_count += 1
    
    # Clear session cache
    session_keys = [key for key in session.keys() if key.startswith('group_member_')]
    for key in session_keys:
        session.pop(key, None)
        cleared_count += 1
    
    if cleared_count > 0:
        current_app.logger.info(
            f"Cleared {cleared_count} group membership cache entries "
            f"(server + session caches)"
        )
