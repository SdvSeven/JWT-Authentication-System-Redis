"""
API роуты для аутентификации и авторизации.

Endpoints:
- POST /auth/register - Регистрация
- POST /auth/login - Вход (выдача токенов)
- POST /auth/logout - Выход (отзыв токенов)
- POST /auth/refresh - Обновление токенов
- POST /auth/revoke-all - Отзыв всех токенов пользователя
- GET /auth/sessions - Список активных сессий
"""

from datetime import timedelta

from fastapi import APIRouter, HTTPException, status, Depends, Request

from app.core.config import get_settings
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_token_remaining_ttl,
)
from app.services.redis_service import redis_service
from app.database.users import user_db
from app.models.schemas import (
    UserRegister,
    UserLogin,
    TokenPair,
    TokenRefresh,
    UserResponse,
    SessionInfo,
    AnomalyReport,
)
from app.api.dependencies import (
    get_current_user,
    get_current_token,
    get_device_fingerprint,
    get_client_ip,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister):
    """
    Регистрация нового пользователя.
    
    - **username**: уникальное имя пользователя (3-50 символов)
    - **email**: уникальный email
    - **password**: пароль (минимум 8 символов)
    - **role**: роль пользователя (admin/user)
    """
    # Проверка существования пользователя
    if user_db.get_by_username(user_data.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Пользователь с таким username уже существует"
        )
    
    if user_db.get_by_email(user_data.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Пользователь с таким email уже существует"
        )
    
    # Создание пользователя
    user = user_db.create_user(
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        role=user_data.role
    )
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active
    )


@router.post("/login", response_model=TokenPair)
async def login(
    credentials: UserLogin,
    request: Request
):
    """
    Аутентификация пользователя.
    
    Возвращает пару токенов:
    - **access_token**: для доступа к ресурсам (живёт 15 минут)
    - **refresh_token**: для обновления access_token (живёт 7 дней)
    
    Также выполняет:
    - Rate limiting (защита от брутфорса)
    - Запись fingerprint устройства
    - Обнаружение аномалий
    """
    client_ip = get_client_ip(request)
    
    # Rate limiting
    allowed, remaining = redis_service.check_rate_limit(
        identifier=f"login:{credentials.username}",
        max_attempts=settings.MAX_LOGIN_ATTEMPTS,
        window_seconds=settings.LOGIN_LOCKOUT_MINUTES * 60
    )
    
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Слишком много попыток. Повторите через {settings.LOGIN_LOCKOUT_MINUTES} минут"
        )
    
    # Проверка пользователя
    user = user_db.get_by_username(credentials.username)
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Неверные учётные данные. Осталось попыток: {remaining}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Аккаунт деактивирован"
        )
    
    # Сброс rate limit после успешного входа
    redis_service.reset_rate_limit(f"login:{credentials.username}")
    
    # Формируем fingerprint
    device_fingerprint = get_device_fingerprint(request)
    user_agent = request.headers.get("User-Agent", "unknown")
    
    # Проверка аномалий
    anomalies = redis_service.record_login(
        user_id=user.id,
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    # Создаём токены
    token_data = {
        "sub": user.id,
        "username": user.username,
        "role": user.role.value,
    }
    
    access_token = create_access_token(
        data=token_data,
        device_fingerprint=device_fingerprint
    )
    
    refresh_token = create_refresh_token(
        data=token_data,
        device_fingerprint=device_fingerprint
    )
    
    # Добавляем refresh token в whitelist
    refresh_ttl = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    redis_service.add_to_whitelist(
        user_id=user.id,
        refresh_token=refresh_token,
        device_info={
            "ip": client_ip,
            "user_agent": user_agent,
            "anomalies": anomalies
        },
        ttl_seconds=refresh_ttl
    )
    
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    token_data: tuple = Depends(get_current_token),
    body: TokenRefresh = None
):
    """
    Выход из системы.
    
    - Добавляет access token в blacklist
    - Удаляет refresh token из whitelist
    """
    access_token, payload = token_data
    
    # Access token в blacklist
    ttl = get_token_remaining_ttl(access_token)
    redis_service.add_to_blacklist(access_token, ttl)
    
    # Refresh token из whitelist (если передан)
    if body and body.refresh_token:
        redis_service.remove_from_whitelist(payload.sub, body.refresh_token)


@router.post("/refresh", response_model=TokenPair)
async def refresh_tokens(
    body: TokenRefresh,
    request: Request
):
    """
    Обновление токенов.
    
    Реализует Refresh Token Rotation:
    - Старый refresh token удаляется
    - Выдаётся новая пара токенов
    
    Это защищает от replay attack:
    если токен украден и использован дважды,
    оригинальный владелец обнаружит проблему.
    """
    # Декодируем refresh token
    payload = decode_token(body.refresh_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token недействителен или истёк"
        )
    
    # Проверяем тип токена
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный тип токена"
        )
    
    user_id = payload.get("sub")
    
    # Проверяем whitelist
    if not redis_service.is_in_whitelist(user_id, body.refresh_token):
        # Токен не в whitelist — возможно уже использован (replay attack)
        # или был отозван. Для безопасности отзываем ВСЕ токены пользователя
        redis_service.revoke_all_user_tokens(user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token недействителен. Все сессии завершены по соображениям безопасности."
        )
    
    # Получаем пользователя
    user = user_db.get_by_id(user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь не найден или деактивирован"
        )
    
    # Удаляем старый refresh token (Rotation)
    redis_service.remove_from_whitelist(user_id, body.refresh_token)
    
    # Создаём новую пару токенов
    device_fingerprint = get_device_fingerprint(request)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "unknown")
    
    token_data = {
        "sub": user.id,
        "username": user.username,
        "role": user.role.value,
    }
    
    new_access_token = create_access_token(
        data=token_data,
        device_fingerprint=device_fingerprint
    )
    
    new_refresh_token = create_refresh_token(
        data=token_data,
        device_fingerprint=device_fingerprint
    )
    
    # Новый refresh token в whitelist
    refresh_ttl = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    redis_service.add_to_whitelist(
        user_id=user.id,
        refresh_token=new_refresh_token,
        device_info={
            "ip": client_ip,
            "user_agent": user_agent,
            "rotated_from": "previous_token"
        },
        ttl_seconds=refresh_ttl
    )
    
    return TokenPair(
        access_token=new_access_token,
        refresh_token=new_refresh_token
    )


@router.post("/revoke-all", status_code=status.HTTP_200_OK)
async def revoke_all_tokens(
    token_data: tuple = Depends(get_current_token)
):
    """
    Отзыв всех токенов пользователя.
    
    Используется когда:
    - Подозрение на утечку токена
    - Смена пароля
    - Выход со всех устройств
    """
    access_token, payload = token_data
    
    # Отзываем все refresh токены
    revoked_count = redis_service.revoke_all_user_tokens(payload.sub)
    
    # Текущий access token в blacklist
    ttl = get_token_remaining_ttl(access_token)
    redis_service.add_to_blacklist(access_token, ttl)
    
    return {
        "message": "Все сессии завершены",
        "revoked_sessions": revoked_count
    }


@router.get("/sessions", response_model=list[SessionInfo])
async def get_sessions(
    token_data: tuple = Depends(get_current_token)
):
    """
    Получение списка активных сессий пользователя.
    
    Позволяет пользователю видеть, где он авторизован.
    """
    _, payload = token_data
    
    sessions = redis_service.get_user_sessions(payload.sub)
    return [SessionInfo(**s) for s in sessions]
