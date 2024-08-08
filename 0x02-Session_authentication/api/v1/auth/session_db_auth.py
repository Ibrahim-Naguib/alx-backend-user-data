#!/usr/bin/env python3
"""
Define class SessionDButh
"""
from .session_exp_auth import SessionExpAuth
from models.user_session import UserSession
from datetime import (
    datetime,
    timedelta
)
from models.base import TIMESTAMP_FORMAT


class SessionDBAuth(SessionExpAuth):
    """
    Definition of SessionDBAuth class that persists session data
    in a database
    """
    def __init__(self):
        super().__init__()
        UserSession.load_from_file()

    def create_session(self, user_id=None):
        """
        Create a Session ID for a user_id
        Args:
           user_id (str): user id
        """
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        kw = {
            "user_id": user_id,
            "session_id": session_id,
        }
        user = UserSession(**kw)
        user.save()
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """
        Returns a user ID based on a session ID
        Args:
            session_id (str): session ID
        Return:
            user id or None if session_id is None or not a string
        """
        if session_id is None:
            return None

        user_sessions = UserSession.search({"session_id": session_id})
        if not user_sessions:
            return None

        user_session = user_sessions[0]

        created_at = user_session.created_at
        if isinstance(created_at, str):
            created_at = datetime.strptime(created_at, TIMESTAMP_FORMAT)

        if self.session_duration <= 0:
            return user_session.user_id

        allowed_window = created_at + timedelta(seconds=self.session_duration)
        if allowed_window < datetime.now():
            user_session.remove()
            return None

        return user_session.user_id

    def destroy_session(self, request=None):
        """
        Destroy a UserSession instance based on a
        Session ID from a request cookie
        """
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if not session_id:
            return False
        user_session = UserSession.search({"session_id": session_id})
        if user_session:
            user_session[0].remove()
            return True
        return False
