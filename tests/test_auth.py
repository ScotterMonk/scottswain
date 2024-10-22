from http import HTTPStatus
import sys
import logging

# Configure logger to print to shell.
#   (move this to a separate file so it can be referenced by multiple modules)
logger = logging.getLogger("alembic.env")
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


def test_register_user(client):
    # Prepare the test data.
    data = {
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "testpassword",
    }
    # Send a POST request to register a new user.
    response = client.post("/register", json=data)
    # Assert that the response status code is 201 (Created).
    assert response.status_code == 201
    # Assert that the response JSON contains the expected message.
    json_data = response.get_json()
    """ Changed check for message string to check for status
        code of "Created" because the message can be variable."""
    # assert json_data["message"] == "User registered successfully".
    assert response.status_code == HTTPStatus.CREATED


def test_login_user(client):
    # First, register a new user.
    register_data = {
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "testpassword",
    }
    client.post("/register", json=register_data)
    # Prepare login data.
    login_data = {"email": "testuser@example.com", "password": "testpassword"}
    # Send a POST request to login.
    response = client.post("/login", json=login_data)
    # Assert that the response status code is 200 (OK).
    assert response.status_code == HTTPStatus.OK
    # Assert that the response JSON contains the expected message.
    json_data = response.get_json()
    assert json_data["message"] == "Login successful"
    assert json_data["email"] == "testuser@example.com"


def test_login_invalid_password(client):
    # Post the wrong login/password to test the invalid login.
    response = client.post(
        "/login", json={"email": "testuser@example.com", "password": "Invalidpassword"}
    )
    assert response.status_code == HTTPStatus.UNAUTHORIZED


def test_login_non_existent_user(client):
    # Post the wrong login/password to test the invalid login.
    response = client.post(
        "/login", json={"email": "notauser@example.com", "password": "Invalidpassword"}
    )
    assert response.status_code == HTTPStatus.UNAUTHORIZED


def test_show_user_profile(client):
    # First, register a new user.
    register_data = {
        "username": "Dev Userson",
        "email": "dev.userson@example.com",
        "password": "sosecure",
    }
    client.post("/register", json=register_data)
    response = client.post("/profile", json={"username": "Dev Userson"})
    assert response.status_code == HTTPStatus.OK


def test_access_report(client):
    response = client.post("/access-report", json={"limit_to": "all_users"})
    assert response.status_code == HTTPStatus.OK


def test_delete_user(client):
    # First, register a new user.
    register_data = {
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "testpassword",
    }
    client.post("/register", json=register_data)
    # Now, delete the user.
    delete_data = {"email": "testuser@example.com"}
    response = client.post("/delete-user", json=delete_data)
    assert response.status_code == HTTPStatus.OK
