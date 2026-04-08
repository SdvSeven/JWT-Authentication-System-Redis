"""
Тесты для JWT Auth System.

Запуск: pytest tests/ -v
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

# Мокаем Redis перед импортом app
@pytest.fixture(autouse=True)
def mock_redis():
    """Мок Redis для тестов."""
    with patch('app.services.redis_service.redis_service') as mock:
        # Настраиваем базовое поведение
        mock.health_check.return_value = True
        mock.is_blacklisted.return_value = False
        mock.is_in_whitelist.return_value = True
        mock.add_to_whitelist.return_value = True
        mock.add_to_blacklist.return_value = True
        mock.remove_from_whitelist.return_value = True
        mock.check_rate_limit.return_value = (True, 4)
        mock.reset_rate_limit.return_value = True
        mock.record_login.return_value = {}
        mock.get_user_sessions.return_value = []
        mock.revoke_all_user_tokens.return_value = 1
        yield mock


@pytest.fixture
def client(mock_redis):
    """Тестовый клиент FastAPI."""
    from app.main import app
    return TestClient(app)


@pytest.fixture
def admin_token(client):
    """Получение токена админа."""
    response = client.post("/auth/login", json={
        "username": "admin",
        "password": "adminpassword123"
    })
    return response.json()["access_token"]


@pytest.fixture
def user_token(client):
    """Получение токена пользователя."""
    response = client.post("/auth/login", json={
        "username": "user",
        "password": "userpassword123"
    })
    return response.json()["access_token"]


class TestHealth:
    """Тесты health endpoints."""
    
    def test_root(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "service" in response.json()
    
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestAuth:
    """Тесты аутентификации."""
    
    def test_login_success(self, client):
        response = client.post("/auth/login", json={
            "username": "admin",
            "password": "adminpassword123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
    
    def test_login_wrong_password(self, client):
        response = client.post("/auth/login", json={
            "username": "admin",
            "password": "wrongpassword"
        })
        assert response.status_code == 401
    
    def test_login_nonexistent_user(self, client):
        response = client.post("/auth/login", json={
            "username": "nonexistent",
            "password": "password"
        })
        assert response.status_code == 401
    
    def test_register_success(self, client):
        response = client.post("/auth/register", json={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "newpassword123",
            "role": "user"
        })
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["role"] == "user"
    
    def test_register_duplicate_username(self, client):
        response = client.post("/auth/register", json={
            "username": "admin",
            "email": "another@example.com",
            "password": "password123",
            "role": "user"
        })
        assert response.status_code == 409


class TestContent:
    """Тесты контента с ролевым доступом."""
    
    def test_public_content_no_auth(self, client):
        """Публичный контент доступен без авторизации."""
        response = client.get("/content/public")
        assert response.status_code == 200
        assert len(response.json()["items"]) > 0
    
    def test_shared_content_requires_auth(self, client):
        """Общий контент требует авторизации."""
        response = client.get("/content/shared")
        assert response.status_code == 403  # No credentials
    
    def test_shared_content_admin(self, client, admin_token):
        """Админ имеет доступ к общему контенту."""
        response = client.get(
            "/content/shared",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        assert response.json()["user_role"] == "admin"
    
    def test_shared_content_user(self, client, user_token):
        """User имеет доступ к общему контенту."""
        response = client.get(
            "/content/shared",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 200
        assert response.json()["user_role"] == "user"
    
    def test_admin_content_admin_only(self, client, admin_token):
        """Админ-контент доступен только админу."""
        response = client.get(
            "/content/admin",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
    
    def test_admin_content_forbidden_for_user(self, client, user_token):
        """User не имеет доступа к админ-контенту."""
        response = client.get(
            "/content/admin",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 403
    
    def test_user_content_user_only(self, client, user_token):
        """User-контент доступен только user."""
        response = client.get(
            "/content/user",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 200
    
    def test_user_content_forbidden_for_admin(self, client, admin_token):
        """Admin не имеет доступа к user-контенту (демонстрация разделения ролей)."""
        response = client.get(
            "/content/user",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 403


class TestSecurity:
    """Тесты безопасности."""
    
    def test_invalid_token(self, client):
        """Невалидный токен отклоняется."""
        response = client.get(
            "/content/shared",
            headers={"Authorization": "Bearer invalid.token.here"}
        )
        assert response.status_code == 401
    
    def test_missing_token(self, client):
        """Отсутствующий токен -> 403."""
        response = client.get("/content/shared")
        assert response.status_code == 403
