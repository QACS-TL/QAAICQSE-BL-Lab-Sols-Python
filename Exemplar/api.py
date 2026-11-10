import os
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request

try:
    from .user_manager import UserManager
except ImportError:
    from user_manager import UserManager


def create_app(user_manager=None, config=None):
    app = Flask(__name__)
    app.config.update(config or {})

    if user_manager is None:
        secret_key = app.config.get("JWT_SECRET_KEY") or os.environ.get(
            "JWT_SECRET_KEY"
        )
        if not secret_key:
            raise ValueError("Set JWT_SECRET_KEY before creating the API")
        user_manager = UserManager(
            app.config.get("DATABASE", "users.db"), secret_key=secret_key
        )
    app.extensions["user_manager"] = user_manager
    app.add_url_rule("/users", view_func=_register_user(user_manager), methods=["POST"])
    app.add_url_rule(
        "/auth/login", view_func=_login(user_manager), methods=["POST"]
    )
    app.add_url_rule(
        "/auth/reset-password",
        view_func=_reset_password(user_manager),
        methods=["POST"],
    )
    app.add_url_rule(
        "/users/<int:user_id>",
        view_func=_authenticated(user_manager)(_get_user(user_manager)),
        methods=["GET"],
    )
    return app


def _request_payload(required_fields, error_message):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not all(
        field in payload for field in required_fields
    ):
        return None, (jsonify(error=error_message), 400)
    return payload, None


def _register_user(user_manager):
    def handle_registration():
        payload, error = _request_payload(
            ("email", "password", "personal_info"),
            "email, password, and personal_info are required",
        )
        if error:
            return error
        try:
            user = user_manager.register_user(
                payload["email"], payload["password"], payload["personal_info"]
            )
        except (TypeError, ValueError) as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(user=user), 201

    return handle_registration


def _login(user_manager):
    def handle_login():
        payload, error = _request_payload(
            ("email", "password"), "email and password are required"
        )
        if error:
            return error
        result = user_manager.authenticate_user(payload["email"], payload["password"])
        if result is None:
            return jsonify(error="Invalid email or password"), 401
        return jsonify(result), 200

    return handle_login


def _reset_password(user_manager):
    def handle_reset():
        payload, error = _request_payload(
            ("email", "new_password", "reset_token"),
            "email, new_password, and reset_token are required",
        )
        if error:
            return error
        try:
            changed = user_manager.reset_password(
                payload["email"], payload["new_password"], payload["reset_token"]
            )
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        if not changed:
            return jsonify(error="Invalid reset token"), 400
        return jsonify(message="Password reset"), 200

    return handle_reset


def _get_user(user_manager):
    def handle_get_user(user_id):
        if str(user_id) != str(g.user_id):
            return jsonify(error="Forbidden"), 403
        user = user_manager.get_user_data(user_id, g.user_id)
        if user is None:
            return jsonify(error="User not found"), 404
        return jsonify(user=user), 200

    return handle_get_user


def _authenticated(user_manager):
    def decorate(handler):
        @wraps(handler)
        def wrapped(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() != "bearer" or not token:
                return jsonify(error="Authentication required"), 401
            try:
                claims = jwt.decode(
                    token, user_manager.secret_key, algorithms=["HS256"]
                )
            except jwt.InvalidTokenError:
                return jsonify(error="Invalid or expired token"), 401
            if claims.get("type") != "access":
                return jsonify(error="Invalid or expired token"), 401
            g.user_id = claims.get("sub")
            return handler(*args, **kwargs)

        return wrapped

    return decorate