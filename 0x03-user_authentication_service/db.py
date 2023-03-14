#!/usr/bin/env python3
"""Defines the database connection"""
from typing import Dict

from sqlalchemy import create_engine
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session

from user import Base, User


class DB:
    """DB class"""

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Saves a user to the database

        Args:
            email (str): user's email
            hashed_password (str): user's password

        Returns:
            User: User object
        """

        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs: Dict) -> User:
        """Finds user by keyword

        Args:
            keyword (str): keyword

        Raises:
            InvalidRequestError: invalid request
            NoResultFound: No user found

        Returns:
            User: User object
        """

        users = self._session.query(User).all()
        for key, value in kwargs.items():
            if key not in User.__dict__:
                raise InvalidRequestError
            for user in users:
                if getattr(user, key) == value:
                    return user
        raise NoResultFound

    def update_user(self, user_id: int, **kwargs) -> None:
        """Updates a user"""
        try:
            user = self.find_user_by(id=user_id)
        except NoResultFound:
            raise ValueError

        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
            else:
                raise ValueError
        self._session.add(user)
        self._session.commit()
