#!/usr/bin/env python3
from os import getenv

from flask import abort, jsonify, make_response, request

from api.v1.views import app_views
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """Session login

    POST /auth_session/login
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if email is None:
        return jsonify({"error": "email missing"}), 400
    if password is None:
        return jsonify({"error": "password missing"}), 400

    users = User.search({"email": email})
    if users is None or len(users) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    for user in users:
        if user.is_valid_password(password):
            from api.v1.app import auth
            session_id = auth.create_session(user.id)
            res = make_response(jsonify(user.to_json()))
            res.set_cookie(getenv("SESSION_NAME", session_id))
            return res
    return jsonify({"error": "wrong password"}), 401


@app_views.route(
        'auth_session/logout',
        methods=['DELETE'],
        strict_slashes=False
        )
def logout():
    """Session logout

    POST /auth_session/logout
    """
    from api.v1.app import auth
    logout = auth.destroy_session(request)
    if not logout:
        return jsonify({}), 200
    return abort(404)
