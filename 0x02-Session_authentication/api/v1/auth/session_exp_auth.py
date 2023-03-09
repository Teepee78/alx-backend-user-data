#!/usr/bin/env python3
"""Session Authentication with expiration"""
from datetime import datetime, timedelta
from os import getenv

from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """Session Authentication with expiration"""

    def __init__(self):
        """Initialize the session"""
        try:
            self.session_duration = int(getenv('SESSION_DURATION'))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """Create a new session"""

        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        session_dictionary = {
            "user_id": user_id,
            "created_at": datetime.now()
        }
        self.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Get user_id"""

        if session_id is None:
            return None
        user = self.user_id_by_session_id.get(session_id)
        if user is None:
            return None
        created_at = user.get("created_at")
        if created_at == 0:
            return user.get("user_id")
        if created_at is None:
            return None
        window = created_at + timedelta(seconds=self.session_duration)
        if window < datetime.now():
            return None
        return user.get("user_id")
