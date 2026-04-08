"""
In-memory хранилище пользователей.

В реальном проекте это была бы PostgreSQL/MongoDB,
но для демонстрации JWT+Redis используем словарь.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.schemas import Role, UserInDB
from app.core.security import hash_password


class UserDatabase:
    """Имитация базы данных пользователей."""
    
    def __init__(self):
        self._users: dict[str, dict[str, Any]] = {}
        self._username_index: dict[str, str] = {}
        self._email_index: dict[str, str] = {}
        
        # Создаём тестовых пользователей
        self._create_test_users()
    
    def _create_test_users(self):
        """Создание тестовых пользователей."""
        # Админ
        self.create_user(
            username="admin",
            email="admin@example.com",
            password="adminpassword123",
            role=Role.ADMIN
        )
        
        # Обычный пользователь
        self.create_user(
            username="user",
            email="user@example.com",
            password="userpassword123",
            role=Role.USER
        )
    
    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: Role = Role.USER
    ) -> UserInDB | None:
        """Создание нового пользователя."""
        # Проверка уникальности
        if username in self._username_index:
            return None
        if email in self._email_index:
            return None
        
        user_id = str(uuid.uuid4())
        
        user_data = {
            "id": user_id,
            "username": username,
            "email": email,
            "hashed_password": hash_password(password),
            "role": role,
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        self._users[user_id] = user_data
        self._username_index[username] = user_id
        self._email_index[email] = user_id
        
        return UserInDB(**user_data)
    
    def get_by_id(self, user_id: str) -> UserInDB | None:
        """Получение пользователя по ID."""
        user_data = self._users.get(user_id)
        if user_data:
            return UserInDB(**user_data)
        return None
    
    def get_by_username(self, username: str) -> UserInDB | None:
        """Получение пользователя по username."""
        user_id = self._username_index.get(username)
        if user_id:
            return self.get_by_id(user_id)
        return None
    
    def get_by_email(self, email: str) -> UserInDB | None:
        """Получение пользователя по email."""
        user_id = self._email_index.get(email)
        if user_id:
            return self.get_by_id(user_id)
        return None
    
    def update_password(self, user_id: str, new_password: str) -> bool:
        """Обновление пароля пользователя."""
        if user_id in self._users:
            self._users[user_id]["hashed_password"] = hash_password(new_password)
            return True
        return False
    
    def deactivate_user(self, user_id: str) -> bool:
        """Деактивация пользователя."""
        if user_id in self._users:
            self._users[user_id]["is_active"] = False
            return True
        return False


# Singleton instance
user_db = UserDatabase()
