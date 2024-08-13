#!/usr/bin/env python3
"""Authentication module"""

import bcrypt
from bcrypt import checkpw
import uuid
from uuid import uuid4
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Hashes a password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generates a UUID.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database
    """

    def __init__(self) -> None:
        '''Initializes a new auth instance
        '''
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        '''Registers new user to the database
        '''
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hass_pass = _hash_password(password)
            user = self._db.add_user(email=email, hashed_password=hass_pass)
            return user
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """Validates a user's login credentials."""
        try:
            user = self._db.find_user_by(email=email)
            if checkpw(password.encode(), user.hashed_password):
                return True
        except NoResultFound:
            pass
        return False

    def create_session(self, email: str) -> str:
        """Creates a new session for the user and returns the session ID."""
        try:
            user = self._db.find_user_by(email=email)
            session_id = str(uuid.uuid4())
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieves a user based on a given session ID.
        """
            user = None
            if session_id is None:
                return None
            try:
                user = self._db.find_user_by(session_id=session_id)
            except NoResultFound:
                return None
            return user
