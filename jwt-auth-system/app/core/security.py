"""
Модуль безопасности: JWT токены и хеширование паролей.

Реализует:
- Генерация и валидация JWT токенов
- Хеширование паролей с bcrypt
- Device fingerprinting для защиты от кражи токенов
"""

import jwt
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()

# Контекст для хеширования паролей
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.BCRYPT_ROUNDS
)


def hash_password(password: str) -> str:
    """Хеширование пароля."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    data: dict[str, Any],
    device_fingerprint: str | None = None,
    expires_delta: timedelta | None = None
) -> str:
    """
    Создание Access Token.
    
    Короткоживущий токен (15 минут по умолчанию) для доступа к ресурсам.
    Содержит fingerprint устройства для защиты от кражи.
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    })
    
    # Добавляем fingerprint устройства для привязки токена
    if device_fingerprint:
        to_encode["fingerprint"] = hash_fingerprint(device_fingerprint)
    
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


def create_refresh_token(
    data: dict[str, Any],
    device_fingerprint: str | None = None,
    expires_delta: timedelta | None = None
) -> str:
    """
    Создание Refresh Token.
    
    Долгоживущий токен (7 дней по умолчанию) для обновления access token.
    Хранится в whitelist Redis для возможности отзыва.
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
    })
    
    if device_fingerprint:
        to_encode["fingerprint"] = hash_fingerprint(device_fingerprint)
    
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


def decode_token(token: str) -> dict[str, Any] | None:
    """
    Декодирование и валидация JWT токена.
    
    Возвращает payload или None если токен невалиден.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        # Токен истёк
        return None
    except jwt.InvalidTokenError:
        # Невалидный токен
        return None


def get_token_expiry(token: str) -> datetime | None:
    """Получение времени истечения токена."""
    payload = decode_token(token)
    if payload and "exp" in payload:
        return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    return None


def get_token_remaining_ttl(token: str) -> int:
    """
    Получение оставшегося времени жизни токена в секундах.
    
    Используется для установки TTL в blacklist.
    """
    expiry = get_token_expiry(token)
    if expiry:
        remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(remaining))
    return 0


def hash_fingerprint(fingerprint: str) -> str:
    """
    Хеширование fingerprint устройства.
    
    Fingerprint содержит: User-Agent, Accept-Language, etc.
    Хешируем для экономии места и конфиденциальности.
    """
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]


def verify_fingerprint(token: str, current_fingerprint: str) -> bool:
    """
    Проверка соответствия fingerprint устройства.
    
    Помогает определить потенциальную кражу токена:
    если fingerprint не совпадает — возможно токен украден.
    """
    payload = decode_token(token)
    if not payload:
        return False
    
    stored_fingerprint = payload.get("fingerprint")
    if not stored_fingerprint:
        return True  # Если fingerprint не был сохранён, пропускаем проверку
    
    return stored_fingerprint == hash_fingerprint(current_fingerprint)
