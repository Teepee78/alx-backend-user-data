#!/usr/bin/env python3
"""Session DB Auth mechanism"""
from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """Session DB Auth mechanism"""

    def create_session(self, user_id=None):
        """Create a new session"""
        if user_id is None:
            return None

        session_id = super().create_session(user_id)
        if not session_id:
            return None
        session = UserSession(user_id=user_id, session_id=session_id)
        session.save()
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Get user_id for a session"""
        if session_id is None:
            return None

        user_session = UserSession.search({"session_id": session_id})
        for user in user_session:
            if user.session_id == session_id:
                return user.user_id
        return None

    def destroy_session(self, request=None):
        """Destroy a session"""
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        user_session = UserSession.search({"session_id": session_id})
        if user_session:
            user_session[0].remove()
            return True
        return False
