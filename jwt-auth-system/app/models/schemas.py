"""
Pydantic модели для валидации данных.
"""

from enum import Enum
from pydantic import BaseModel, EmailStr, Field


class Role(str, Enum):
    """
    Роли пользователей.
    
    ADMIN - администратор, доступ к админ-контенту
    USER - обычный пользователь, доступ к user-контенту
    Обе роли имеют доступ к общему контенту.
    """
    ADMIN = "admin"
    USER = "user"


# ==================== Auth Models ====================

class UserRegister(BaseModel):
    """Модель для регистрации."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    role: Role = Role.USER


class UserLogin(BaseModel):
    """Модель для входа."""
    username: str
    password: str


class TokenPair(BaseModel):
    """Пара токенов: access + refresh."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefresh(BaseModel):
    """Модель для обновления токенов."""
    refresh_token: str


class TokenPayload(BaseModel):
    """Payload JWT токена."""
    sub: str  # user_id
    username: str
    role: Role
    type: str  # "access" или "refresh"
    exp: int
    iat: int
    fingerprint: str | None = None


# ==================== User Models ====================

class UserBase(BaseModel):
    """Базовая модель пользователя."""
    username: str
    email: EmailStr
    role: Role


class UserInDB(UserBase):
    """Модель пользователя в БД."""
    id: str
    hashed_password: str
    is_active: bool = True
    created_at: str


class UserResponse(UserBase):
    """Ответ с данными пользователя."""
    id: str
    is_active: bool


# ==================== Session Models ====================

class SessionInfo(BaseModel):
    """Информация о сессии."""
    created_at: str
    device_info: dict
    token_hash: str


class AnomalyReport(BaseModel):
    """Отчёт об аномалиях при входе."""
    new_device: bool = False
    new_location: bool = False
    first_login: bool = False
    impossible_travel: bool = False


# ==================== Content Models ====================

class ContentItem(BaseModel):
    """Единица контента."""
    id: str
    title: str
    content: str
    access_level: str  # "public", "shared", "admin", "user"


class ContentResponse(BaseModel):
    """Ответ с контентом."""
    items: list[ContentItem]
    user_role: Role | None = None
