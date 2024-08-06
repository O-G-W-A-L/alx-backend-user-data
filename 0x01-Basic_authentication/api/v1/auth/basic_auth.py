#!/usr/bin/env python3
"""Basic Authentication module for the API.
"""
from api.v1.auth.auth import Auth
import re
from typing import Optional


class BasicAuth(Auth):
    """Basic Authentication class inheriting from Auth.
    """
    def extract_base64_authorization_header(
            self,
            authorization_header: Optional[str]) -> Optional[str]:
        """Extracts the Base64 part of the Authorization header
        for Basic Authentication
        """
        if isinstance(authorization_header, str):
            pattern = r'^Basic (?P<token>.+)$'
            field_match = re.fullmatch(pattern, authorization_header.strip())
            if field_match is not None:
                return field_match.group('token')
        return None
