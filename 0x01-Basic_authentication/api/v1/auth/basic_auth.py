#!/usr/bin/env python3
"""Basic Authentication module for the API.
"""
from api.v1.auth.auth import Auth
import re
from typing import Optional, Tuple
import base64
import binascii


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

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: Optional[str]
            ) -> Optional[str]:
        """Decodes a base64-encoded authorization header
        """
        if isinstance(base64_authorization_header, str):
            try:
                res = base64.b64decode(
                        base64_authorization_header,
                        validate=True)
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None
        return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: Optional[str]
            ) -> Optional[Tuple[str, str]]:
        """Extracts user credentials from a base64-decoded authorization
        header that uses the Basic authentication flow
        """
        if isinstance(decoded_base64_authorization_header, str):
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            field_match = re.fullmatch(
                    pattern,
                    decoded_base64_authorization_header.strip())
            if field_match:
                user = field_match.group('user')
                password = field_match.group('password')
                return user, password
        return None, None
