#!/usr/bin/env python3
"""Authentication module for the API.
"""
import re
from typing import List, Optional, TypeVar
from flask import request


class Auth:
    """Authentication class to manage API authentication.
    """

    def require_auth(
            self, path: Optional[str],
            excluded_paths: Optional[List[str]]) -> bool:
        """
        Checks if a path requires authentication
        Returns:
            bool: True if the path requires authentication, False otherwise.
        """
        if not path or not excluded_paths:
            return True

        # Normalize the path for comparison
        normalized_path = path.rstrip('/') + '/'

        for exclusion_path in excluded_paths:
            normalized_exclusion = exclusion_path.rstrip('/') + '/'
            if normalized_exclusion.endswith('*'):
                if normalized_path.startswith(normalized_exclusion[:-1]):
                    return False
            elif normalized_path == normalized_exclusion:
                return False

        return True

    def authorization_header(self, request=None) -> Optional[str]:
        """
        Gets the authorization header field from the request.
        Returns:
            str: The value of the Authorization header, or None if not present.
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None 

    def current_user(self) -> Optional[TypeVar('User')]:
        """
        Gets the current user from the request.
        Returns:
            User: The user object or None if not available.
        """
        return None
