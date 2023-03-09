#!/usr/bin/env python3
"""Session Authentication"""
from os import getenv
from uuid import uuid4

from models.user import User

from .auth import Auth


class SessionAuth(Auth):
    """Session Authentication class"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Create a new session for user

        Args:
            user_id (str, optional): user's id. Defaults to None.

        Returns:
            str: session id
        """
        if user_id is None:
            return None
        if type(user_id) != str:
            return None
        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Gets a user's id by session_id

        Args:
            session_id (str, optional): session_id. Defaults to None.

        Returns:
            str: user_id
        """
        if session_id is None:
            return None
        if type(session_id) != str:
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """Returns the current user

        Args:
            request (request, optional): request. Defaults to None.
        """
        cookie = self.session_cookie(request)
        if cookie is not None:
            user_id = self.user_id_by_session_id.get(cookie)
            return User.get(user_id)
        return None

    def destroy_session(self, request=None):
        """Logs out a user"""

        if request is None:
            return False
        session_id = self.session_cookie(request)
        if id is None:
            return False
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False
        self.user_id_by_session_id.pop(session_id)
        return True
