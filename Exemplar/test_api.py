import pytest
from api import create_app
from user_manager import UserManager


@pytest.fixture
def client(tmp_path):
    manager = UserManager(
        str(tmp_path / "users.db"),
        secret_key="test-secret-key-for-jwt-signing-32-bytes",
    )
    app = create_app(manager, {"TESTING": True})
    yield app.test_client(), manager
    manager.close()


def register(client, email="ada@example.com"):
    return client.post(
        "/users",
        json={"email": email, "password": "correct-horse", "personal_info": "Ada"},
    )


def test_registration_and_login(client):
    http, _ = client
    response = register(http)
    assert response.status_code == 201

    login = http.post(
        "/auth/login", json={"email": "ada@example.com", "password": "correct-horse"}
    )
    assert login.status_code == 200
    assert "token" in login.json
    assert "password" not in login.json["user"]


def test_registration_and_login_errors(client):
    http, _ = client
    assert http.post("/users", json={}).status_code == 400
    assert http.post(
        "/users",
        json={"email": "ada@example.com", "password": "correct-horse", "personal_info": 7},
    ).status_code == 400
    register(http)
    assert register(http).status_code == 400
    assert http.post(
        "/auth/login", json={"email": "ada@example.com", "password": "wrong-pass"}
    ).status_code == 401


def test_profile_requires_valid_token_and_owner(client):
    http, _ = client
    registered = register(http).json["user"]
    token = http.post(
        "/auth/login", json={"email": "ada@example.com", "password": "correct-horse"}
    ).json["token"]

    assert http.get(f"/users/{registered['id']}").status_code == 401
    headers = {"Authorization": f"Bearer {token}"}
    own_profile = http.get(f"/users/{registered['id']}", headers=headers)
    assert own_profile.status_code == 200
    assert own_profile.json["user"]["email"] == "ada@example.com"
    assert http.get("/users/999", headers=headers).status_code == 403


def test_password_reset_requires_a_valid_token(client):
    http, manager = client
    register(http)
    payload = {
        "email": "ada@example.com",
        "new_password": "new-password",
        "reset_token": "invalid",
    }
    assert http.post("/auth/reset-password", json=payload).status_code == 400

    payload["reset_token"] = manager.create_password_reset_token("ada@example.com")
    assert http.post("/auth/reset-password", json=payload).status_code == 200
    assert http.post(
        "/auth/login", json={"email": "ada@example.com", "password": "new-password"}
    ).status_code == 200