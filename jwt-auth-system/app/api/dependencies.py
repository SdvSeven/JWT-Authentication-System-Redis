"""
FastAPI Dependencies для аутентификации и авторизации.

Реализует:
- Извлечение и валидация JWT из заголовка Authorization
- Проверка blacklist/whitelist
- Проверка fingerprint устройства
- Ролевой доступ
"""

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.security import (
    decode_token,
    verify_fingerprint,
)
from app.services.redis_service import redis_service
from app.database.users import user_db
from app.models.schemas import Role, UserInDB, TokenPayload


# Схема Bearer Token
security = HTTPBearer()


def get_device_fingerprint(request: Request) -> str:
    """
    Формирование fingerprint устройства из заголовков запроса.
    
    Используется для привязки токена к устройству.
    """
    user_agent = request.headers.get("User-Agent", "")
    accept_language = request.headers.get("Accept-Language", "")
    accept_encoding = request.headers.get("Accept-Encoding", "")
    
    # В реальном приложении можно добавить больше параметров
    return f"{user_agent}|{accept_language}|{accept_encoding}"


def get_client_ip(request: Request) -> str:
    """Получение IP адреса клиента."""
    # Учитываем возможный прокси
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def get_current_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    request: Request = None
) -> tuple[str, TokenPayload]:
    """
    Извлечение и валидация access token.
    
    Проверяет:
    1. Валидность JWT подписи
    2. Не истёк ли токен
    3. Тип токена (должен быть access)
    4. Не в blacklist ли токен
    5. Соответствие fingerprint устройства (опционально)
    """
    token = credentials.credentials
    
    # Декодируем токен
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Токен недействителен или истёк",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Проверяем тип токена
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный тип токена",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Проверяем blacklist
    if redis_service.is_blacklisted(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Токен был отозван",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Проверяем fingerprint (если есть)
    if request and payload.get("fingerprint"):
        current_fingerprint = get_device_fingerprint(request)
        if not verify_fingerprint(token, current_fingerprint):
            # Потенциальная кража токена!
            # В реальном приложении здесь можно:
            # 1. Залогировать инцидент
            # 2. Уведомить пользователя
            # 3. Добавить токен в blacklist
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Подозрительная активность: несоответствие устройства",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    return token, TokenPayload(**payload)


async def get_current_user(
    token_data: tuple[str, TokenPayload] = Depends(get_current_token)
) -> UserInDB:
    """Получение текущего пользователя из токена."""
    _, payload = token_data
    
    user = user_db.get_by_id(payload.sub)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь не найден",
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Пользователь деактивирован",
        )
    
    return user


def require_role(*allowed_roles: Role):
    """
    Фабрика зависимостей для проверки роли.
    
    Использование:
        @app.get("/admin", dependencies=[Depends(require_role(Role.ADMIN))])
    """
    async def role_checker(
        user: UserInDB = Depends(get_current_user)
    ) -> UserInDB:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Требуется роль: {', '.join([r.value for r in allowed_roles])}",
            )
        return user
    
    return role_checker


# Готовые зависимости для ролей
RequireAdmin = Depends(require_role(Role.ADMIN))
RequireUser = Depends(require_role(Role.USER))
RequireAnyRole = Depends(require_role(Role.ADMIN, Role.USER))
