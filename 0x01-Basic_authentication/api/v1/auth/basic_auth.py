#!/usr/bin/env python3
"""Basic Auth implementation"""
import base64
from typing import TypeVar

from models.user import User

from .auth import Auth


class BasicAuth(Auth):
    """Basic Auth implementation"""

    def extract_base64_authorization_header(
            self,
            authorization_header: str
    ) -> str:
        """Extracts the authorization header

        Args:
            authorization_header (str): authorization header

        Returns:
            str: base64 encoded string
        """
        if authorization_header is None:
            return None
        if type(authorization_header) != str:
            return None
        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header.replace("Basic ", "")

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str
    ) -> str:
        """Decodes the authorization header

        Args:
            base64_authorization_header (str): authorization header

        Returns:
            str: decoded header
        """
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) != str:
            return None

        try:
            decoded = base64.b64decode(base64_authorization_header)
        except Exception:
            return None
        return decoded.decode('utf-8')

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
    ):
        """Extracts the user credentials

        Args:
            decoded_base64_authorization_header (str): header to extract

        Returns:
            Tuple of extracted credentials
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if type(decoded_base64_authorization_header) != str:
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None
        email = decoded_base64_authorization_header.split(":")[0]
        password = decoded_base64_authorization_header[len(email) + 1:]
        return email, password

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str
    ) -> TypeVar('User'):
        """Returns a User object from credentials

        Args:
            user_email (str): email
            user_pwd (str): password

        Returns:
            User object
        """
        if user_email is None or type(user_email) != str:
            return None
        if user_pwd is None or type(user_pwd) != str:
            return None

        try:
            users = User.search({"email": user_email})
            if not users or len(users) == 0:
                return None
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
            return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Extracts the current user"""
        header = self.authorization_header(request)
        base = self.extract_base64_authorization_header(header)
        decoded = self.decode_base64_authorization_header(base)
        cred = self.extract_user_credentials(decoded)
        user = self.user_object_from_credentials(cred[0], cred[1])
        return user
