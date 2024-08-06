#!/usr/bin/env python3
""" Auth class for managing API authentication
"""
from flask import request
from typing import List, TypeVar

User = TypeVar('User')


class Auth:
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Returns False - path and excluded_paths will be used later """
        return False

    def authorization_header(self, request=None) -> str:
        """ Returns None - request will be the Flask request object """
        return None

    def current_user(self, request=None) -> User:
        """ Returns None - request will be the Flask request object """
        return None
