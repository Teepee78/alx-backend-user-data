#!/usr/bin/env python3
"""Authentication provider"""
from typing import List, TypeVar

from flask import request


class Auth:
    """Authentication class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if the given path requires authentication

        Args:
            path (str): path to check
            excluded_paths (List[str]): paths that do not
                require authentication

        Returns:
            bool: True if the given path requires authentication
                False otherwise
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        if path.endswith("/"):
            if path in excluded_paths:
                return False
        else:
            for i in excluded_paths:
                if i.startswith(path):
                    return False
                if path.startswith(i):
                    return False
                if i.endswith("*"):
                    if path.startswith(i[:-1]):
                        return False
            if "{}/".format(path) in excluded_paths:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Returns the authorization header

        Args:
            request (request, optional): the request object
                Defaults to None.

        Returns:
            str: the authorization header
            None: otherwise
        """
        if request is None:
            return None

        headers = request.headers
        if headers.get('Authorization') is None:
            return None

        return headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns the current user"""
        return None
