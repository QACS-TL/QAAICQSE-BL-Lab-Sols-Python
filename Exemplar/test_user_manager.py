import pytest
from Lab3 import UserManager


@pytest.fixture
def manager(tmp_path):
    instance = UserManager(
        str(tmp_path / "users.db"),
        secret_key="test-secret-key-for-jwt-signing-32-bytes",
    )
    yield instance
    instance.close()


def test_register_and_authenticate_user(manager):
    created = manager.register_user("User@example.com", "correct-horse", "Ada")
    result = manager.authenticate_user("user@example.com", "correct-horse")

    assert created["email"] == "user@example.com"
    assert result["user"]["personal_info"] == "Ada"
    assert "password" not in result["user"]
    assert manager.authenticate_user("user@example.com", "wrong-pass") is None


def test_registration_validates_fields_and_duplicate_email(manager):
    with pytest.raises(ValueError):
        manager.register_user("not-an-email", "correct-horse", "Ada")
    with pytest.raises(ValueError):
        manager.register_user("ada@example.com", "short", "Ada")

    manager.register_user("ada@example.com", "correct-horse", "Ada")
    with pytest.raises(ValueError):
        manager.register_user("ADA@example.com", "correct-horse", "Ada")


def test_reset_password_requires_a_matching_reset_token(manager):
    manager.register_user("ada@example.com", "correct-horse", "Ada")
    token = manager.create_password_reset_token("ada@example.com")

    assert not manager.reset_password("ada@example.com", "new-password", "invalid")
    assert manager.reset_password("ada@example.com", "new-password", token)
    assert manager.authenticate_user("ada@example.com", "new-password") is not None
    assert manager.authenticate_user("ada@example.com", "correct-horse") is None


def test_user_data_is_available_only_to_the_same_user(manager):
    created = manager.register_user("ada@example.com", "correct-horse", "Ada")

    assert manager.get_user_data(created["id"], created["id"])["email"] == "ada@example.com"
    assert manager.get_user_data(created["id"], 999) is None
    assert manager.get_user_data(999, 999) is None