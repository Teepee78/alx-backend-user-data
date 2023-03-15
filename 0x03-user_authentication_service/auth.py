#!/usr/bin/env python3
"""Authentication methods"""
from typing import Union
from uuid import uuid4

import bcrypt
from sqlalchemy.exc import NoResultFound

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hashes a password

    Args:
        password (str): password

    Returns:
        bytes: hashed password
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generates random uuid"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user

        Args:
            email (str): user's email
            password (str): user's password

        Raises:
            ValueError: If user exists

        Returns:
            User: User Object
        """

        # Check if user exists
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            hashed = _hash_password(password)
            user = self._db.add_user(email, hashed)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates user login

        Args:
            email (str): user's email
            password (str): user's password

        Returns:
            bool: True if password is correct, False otherwise
        """

        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        if bcrypt.checkpw(password.encode(), user.hashed_password):
            return True
        return False

    def create_session(self, email: str) -> str:
        """Creates a session for user

        Args:
            email (str): user's email

        Returns:
            str: uuid of session as a string
        """

        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Gets a user by session_id

        Args:
            session_id (str): session id

        Returns:
            Union[User, None]: User object or None
        """

        if session_id is None:
            return None

        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session"""

        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Gets the token to reset a user's password

        Args:
            email (str): user's email

        Returns:
            str: reset token
        """

        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        token = _generate_uuid()
        self._db.update_user(user.id, reset_token=token)
        return token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password

        Args:
            reset_token (str): reset token
            password (str): new password
        """

        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        hashed_password = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=hashed_password,
            reset_token=None
        )
