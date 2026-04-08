"""
Redis Service: управление whitelist и blacklist токенов.

Whitelist (Белый список):
- Хранит активные refresh токены
- Структура: whitelist:{user_id}:{jti} -> token_data

Blacklist (Чёрный список):
- Хранит отозванные access токены
- Структура: blacklist:{token_hash} -> 1
- TTL = оставшееся время жизни токена

Дополнительно:
- Отслеживание сессий пользователя
- Rate limiting для защиты от брутфорса
- Обнаружение аномалий
"""

import redis
import json
import hashlib
from datetime import datetime, timezone
from typing import Any

from app.core.config import get_settings

settings = get_settings()


class RedisService:
    """Сервис для работы с Redis."""
    
    # Префиксы ключей
    WHITELIST_PREFIX = "whitelist"
    BLACKLIST_PREFIX = "blacklist"
    SESSION_PREFIX = "session"
    RATE_LIMIT_PREFIX = "rate_limit"
    USER_TOKENS_PREFIX = "user_tokens"
    
    def __init__(self):
        self._redis: redis.Redis | None = None
    
    @property
    def redis(self) -> redis.Redis:
        """Lazy initialization Redis соединения."""
        if self._redis is None:
            self._redis = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB,
                password=settings.REDIS_PASSWORD,
                decode_responses=True
            )
        return self._redis
    
    def _hash_token(self, token: str) -> str:
        """Хеширование токена для использования в качестве ключа."""
        return hashlib.sha256(token.encode()).hexdigest()[:32]
    
    # ==================== WHITELIST ====================
    
    def add_to_whitelist(
        self,
        user_id: str,
        refresh_token: str,
        device_info: dict[str, Any],
        ttl_seconds: int
    ) -> bool:
        """
        Добавление refresh token в whitelist.
        
        Сохраняем информацию о сессии:
        - IP адрес
        - User-Agent
        - Время создания
        - Геолокация (если доступна)
        """
        token_hash = self._hash_token(refresh_token)
        key = f"{self.WHITELIST_PREFIX}:{user_id}:{token_hash}"
        
        session_data = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "device_info": device_info,
            "token_hash": token_hash
        }
        
        # Сохраняем токен в whitelist
        self.redis.setex(key, ttl_seconds, json.dumps(session_data))
        
        # Добавляем в список токенов пользователя (для отзыва всех)
        user_tokens_key = f"{self.USER_TOKENS_PREFIX}:{user_id}"
        self.redis.sadd(user_tokens_key, token_hash)
        self.redis.expire(user_tokens_key, ttl_seconds)
        
        return True
    
    def is_in_whitelist(self, user_id: str, refresh_token: str) -> bool:
        """Проверка наличия refresh token в whitelist."""
        token_hash = self._hash_token(refresh_token)
        key = f"{self.WHITELIST_PREFIX}:{user_id}:{token_hash}"
        return self.redis.exists(key) == 1
    
    def remove_from_whitelist(self, user_id: str, refresh_token: str) -> bool:
        """Удаление refresh token из whitelist (при logout)."""
        token_hash = self._hash_token(refresh_token)
        key = f"{self.WHITELIST_PREFIX}:{user_id}:{token_hash}"
        
        # Удаляем из whitelist
        self.redis.delete(key)
        
        # Удаляем из списка токенов пользователя
        user_tokens_key = f"{self.USER_TOKENS_PREFIX}:{user_id}"
        self.redis.srem(user_tokens_key, token_hash)
        
        return True
    
    def get_user_sessions(self, user_id: str) -> list[dict[str, Any]]:
        """Получение всех активных сессий пользователя."""
        pattern = f"{self.WHITELIST_PREFIX}:{user_id}:*"
        sessions = []
        
        for key in self.redis.scan_iter(pattern):
            data = self.redis.get(key)
            if data:
                sessions.append(json.loads(data))
        
        return sessions
    
    def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Отзыв всех токенов пользователя.
        
        Используется при:
        - Подозрении на утечку токенов
        - Смене пароля
        - Принудительном выходе со всех устройств
        """
        pattern = f"{self.WHITELIST_PREFIX}:{user_id}:*"
        deleted = 0
        
        for key in self.redis.scan_iter(pattern):
            self.redis.delete(key)
            deleted += 1
        
        # Очищаем список токенов
        user_tokens_key = f"{self.USER_TOKENS_PREFIX}:{user_id}"
        self.redis.delete(user_tokens_key)
        
        return deleted
    
    # ==================== BLACKLIST ====================
    
    def add_to_blacklist(self, access_token: str, ttl_seconds: int) -> bool:
        """
        Добавление access token в blacklist.
        
        TTL устанавливается равным оставшемуся времени жизни токена,
        чтобы не хранить истёкшие токены.
        """
        if ttl_seconds <= 0:
            return True  # Токен уже истёк, не нужно добавлять
        
        token_hash = self._hash_token(access_token)
        key = f"{self.BLACKLIST_PREFIX}:{token_hash}"
        
        self.redis.setex(key, ttl_seconds, "1")
        return True
    
    def is_blacklisted(self, access_token: str) -> bool:
        """Проверка наличия access token в blacklist."""
        token_hash = self._hash_token(access_token)
        key = f"{self.BLACKLIST_PREFIX}:{token_hash}"
        return self.redis.exists(key) == 1
    
    # ==================== RATE LIMITING ====================
    
    def check_rate_limit(
        self,
        identifier: str,
        max_attempts: int,
        window_seconds: int
    ) -> tuple[bool, int]:
        """
        Проверка rate limit.
        
        Возвращает (разрешено, оставшиеся попытки).
        """
        key = f"{self.RATE_LIMIT_PREFIX}:{identifier}"
        
        current = self.redis.get(key)
        if current is None:
            self.redis.setex(key, window_seconds, 1)
            return True, max_attempts - 1
        
        attempts = int(current)
        if attempts >= max_attempts:
            return False, 0
        
        self.redis.incr(key)
        return True, max_attempts - attempts - 1
    
    def reset_rate_limit(self, identifier: str) -> bool:
        """Сброс rate limit (после успешного входа)."""
        key = f"{self.RATE_LIMIT_PREFIX}:{identifier}"
        self.redis.delete(key)
        return True
    
    # ==================== ANOMALY DETECTION ====================
    
    def record_login(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str
    ) -> dict[str, Any]:
        """
        Запись информации о входе для обнаружения аномалий.
        
        Возвращает информацию о потенциальных проблемах:
        - new_device: вход с нового устройства
        - new_location: вход с новой локации (по IP)
        - impossible_travel: невозможное перемещение
        """
        key = f"{self.SESSION_PREFIX}:history:{user_id}"
        
        login_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip_address,
            "user_agent": user_agent
        }
        
        # Получаем историю входов
        history = self.redis.lrange(key, 0, 9)
        
        anomalies = {}
        
        if history:
            last_login = json.loads(history[0])
            
            # Проверка на новое устройство
            if last_login.get("user_agent") != user_agent:
                anomalies["new_device"] = True
            
            # Проверка на новый IP (упрощённо)
            if last_login.get("ip") != ip_address:
                anomalies["new_location"] = True
        else:
            anomalies["first_login"] = True
        
        # Добавляем в историю
        self.redis.lpush(key, json.dumps(login_data))
        self.redis.ltrim(key, 0, 9)  # Храним только последние 10 входов
        self.redis.expire(key, 86400 * 30)  # 30 дней
        
        return anomalies
    
    def health_check(self) -> bool:
        """Проверка подключения к Redis."""
        try:
            self.redis.ping()
            return True
        except redis.ConnectionError:
            return False


# Singleton instance
redis_service = RedisService()
