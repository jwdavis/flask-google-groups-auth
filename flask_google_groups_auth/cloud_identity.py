"""
Google Cloud Identity Groups API integration for checking nested group memberships.

This module uses the Cloud Identity Groups API which supports checking transitive
(nested) group memberships including external members across different domains.
"""

import hashlib
from datetime import datetime

from flask import current_app
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


def get_cloud_identity_service():
    """
    Create Cloud Identity API service with domain-wide delegation.
    
    Uses service account credentials from key file (local) or Secret Manager (Cloud Run).
    The service account must have domain-wide delegation enabled with scope:
        https://www.googleapis.com/auth/cloud-identity.groups.readonly
    
    Returns:
        Resource: Cloud Identity API service
        
    Raises:
        ValueError: If required credentials are not available
    """
    config = current_app.extensions['flask_google_groups_auth']
    delegated_admin_email = config.get_delegated_admin_email()
    service_account_info = config.get_service_account_info()
    scopes = ['https://www.googleapis.com/auth/cloud-identity.groups.readonly']
    
    try:
        current_app.logger.debug(f"Creating Cloud Identity credentials with delegated admin: {delegated_admin_email}")
        
        # Create credentials from service account info (dict)
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=scopes,
            subject=delegated_admin_email
        )
        
        # Build and return the Cloud Identity service
        return build('cloudidentity', 'v1', credentials=credentials)
        
    except Exception as e:
        error_msg = (
            f"Failed to create Cloud Identity service: {e}\n"
            f"Delegated admin: {delegated_admin_email}"
        )
        current_app.logger.error(error_msg)
        raise


def get_group_resource_name(group_email):
    """
    Get the Cloud Identity resource name for a group by its email address.
    
    This function caches the lookup results to minimize API calls since
    group resource names rarely change.
    
    Args:
        group_email: Email address of the Google Group
        
    Returns:
        str: Resource name in format "groups/{group_id}"
        
    Raises:
        HttpError: If the group is not found or API call fails
    """
    # Check cache first
    cache_key = f"group_resource_name_{hashlib.sha256(group_email.encode()).hexdigest()}"
    cache = current_app.extensions.get('group_resource_name_cache', {})
    
    # Cache TTL for group resource names (24 hours - these rarely change)
    cache_ttl = 86400
    
    if cache_key in cache:
        cached_name, cached_time = cache[cache_key]
        age = (datetime.now() - cached_time).total_seconds()
        if age < cache_ttl:
            current_app.logger.debug(
                f"Cache hit for group resource name: {group_email} (age: {age:.0f}s)"
            )
            return cached_name
    
    # Lookup the group resource name
    try:
        service = get_cloud_identity_service()
        
        current_app.logger.debug(f"Looking up group resource name for: {group_email}")
        
        result = service.groups().lookup(
            groupKey_id=group_email
        ).execute()
        
        resource_name = result.get('name')
        
        if not resource_name:
            raise ValueError(f"No resource name found for group: {group_email}")
        
        current_app.logger.info(f"Group {group_email} -> {resource_name}")
        
        # Cache the result
        if 'group_resource_name_cache' not in current_app.extensions:
            current_app.extensions['group_resource_name_cache'] = {}
        current_app.extensions['group_resource_name_cache'][cache_key] = (resource_name, datetime.now())
        
        return resource_name
        
    except HttpError as e:
        if e.resp.status == 404:
            current_app.logger.error(f"Group not found: {group_email}")
            raise ValueError(f"Group not found: {group_email}")
        else:
            current_app.logger.error(f"Error looking up group resource name: {e}")
            raise


def check_transitive_membership(user_email, group_resource_name):
    """
    Check if a user has transitive (nested) membership in a group.
    
    This function supports cross-domain nested memberships. For example:
    - User@external.com is a member of GroupA@domain.com
    - GroupA@domain.com is a member of GroupB@domain.com
    - This function will return True when checking User@external.com in GroupB
    
    Args:
        user_email: Email address of the user to check
        group_resource_name: Cloud Identity resource name of the group (format: "groups/{id}")
        
    Returns:
        bool: True if user has membership (direct or transitive), False otherwise
    """
    try:
        service = get_cloud_identity_service()
        
        current_app.logger.debug(
            f"Checking transitive membership for {user_email} in {group_resource_name}"
        )
        
        # Build the query for the member
        query = f"member_key_id=='{user_email}'"
        
        result = service.groups().memberships().checkTransitiveMembership(
            parent=group_resource_name,
            query=query
        ).execute()
        
        has_membership = result.get('hasMembership', False)
        
        if has_membership:
            current_app.logger.info(
                f"User {user_email} has transitive membership in {group_resource_name}"
            )
        else:
            current_app.logger.info(
                f"User {user_email} does not have membership in {group_resource_name}"
            )
        
        return has_membership
        
    except HttpError as e:
        if e.resp.status == 404:
            # Group or member not found
            current_app.logger.info(
                f"User {user_email} is not a member of {group_resource_name} (404)"
            )
            return False
        else:
            current_app.logger.error(f"Error checking transitive membership: {e}")
            raise


def clear_group_resource_name_cache():
    """
    Clear the cached group resource names.
    
    This should be called if group configurations change.
    """
    if 'group_resource_name_cache' in current_app.extensions:
        cache = current_app.extensions['group_resource_name_cache']
        count = len(cache)
        cache.clear()
        current_app.logger.info(f"Cleared {count} cached group resource names")
