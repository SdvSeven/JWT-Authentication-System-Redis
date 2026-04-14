
# JWT Authentication System с Redis

<p align="center">
  <img src="media/media1.png" alt="Company Image" width="200"/>
</p>

<h3 align="center">Задание для компании ООО ПСЭК</h3>

## О проекте

Проект реализует backend-систему авторизации и аутентификации на основе JWT.
Redis используется для хранения whitelist/blacklist токенов и управления сессиями.
Основной акцент сделан на backend: авторизация, обновление токенов, защита, роли и контейнеризация.

## Архитектура

```
Клиент -> API Gateway -> Redis
                 ├── Авторизация
                 │     ├── Whitelist (refresh tokens)
                 │     └── Blacklist (access tokens)
                 └── Контент
                       ├── public
                       ├── shared
                       ├── admin
                       └── user
```

## Выбранный способ взаимодействия с контентом

Используется Bearer токен в заголовке `Authorization`.

**Почему:**
- JWT делает приложение stateless и упрощает горизонтальное масштабирование.
- Токен передаётся только в заголовках, не в URL.
- Это стандартный подход для API и хорошо поддерживается клиентами.

## Работа с токенами

- **Access token**: короткий срок жизни, используется для доступа к защищённым ресурсам.
- **Refresh token**: долгий срок жизни, используется для получения новой пары токенов.

### Whitelist
- Сохраняются активные refresh токены.
- При входе в систему refresh токен добавляется в whitelist.
- При выходе из системы refresh токен удаляется.
- При обновлении токенов старый refresh токен заменяется на новый.

### Blacklist
- Сохраняются отозванные access токены.
- При выходе access токен добавляется в blacklist с TTL по оставшемуся времени.
- При отзыве всех сессий добавляется текущий access токен.

## Защита от утечки токенов

### Как определять утечку
- Несовпадение устройства/браузера (device fingerprint).
- Резкая смена IP/геолокации.
- Одновременный доступ с разных устройств.
- Аномальная активность в логах.
- Повторное использование refresh токена (refresh token reuse).

### Защита
- Короткий срок жизни access token.
- Refresh token rotation: при обновлении токенов старый refresh токен удаляется.
- Хранение refresh токенов в whitelist и access токенов в blacklist.
- Rate limiting на входные попытки.
- Предполагается использование HTTPS.

## Система ролей

Реализованы роли `ADMIN` и `USER`.

- `ADMIN` имеет доступ к общему и админскому контенту.
- `USER` имеет доступ к общему и пользовательскому контенту.
- У каждой роли есть общий ресурс и эксклюзивный ресурс.

## Запуск

Запускать из каталога, где находятся `docker-compose.yml` и `Dockerfile`.

```bash
docker-compose up --build
```

После запуска API доступен на:

```text
http://localhost:8000
```

Документация OpenAPI доступна на:

```text
http://localhost:8000/docs
```

## Тестовые пользователи

- `admin` / `adminpassword123` — роль `ADMIN`
- `user` / `userpassword123` — роль `USER`

## API

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| POST | /auth/register | Регистрация нового пользователя | Public |
| POST | /auth/login | Аутентификация и выдача токенов | Public |
| POST | /auth/logout | Выход, отзыв access-token и удаление refresh-token | Auth |
| POST | /auth/refresh | Обновление access и refresh токенов | Auth |
| POST | /auth/revoke-all | Отзыв всех токенов пользователя | Auth |
| GET | /auth/sessions | Список активных сессий | Auth |
| GET | /content/public | Публичный контент | Public |
| GET | /content/shared | Общий контент для USER и ADMIN | Auth |
| GET | /content/admin | Контент только для ADMIN | ADMIN |
| GET | /content/user | Контент только для USER | USER |
| GET | /content/my | Контент текущего пользователя | Auth |

## Примеры запросов

### Логин

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"adminpassword123"}'
```

Ответ:

```json
{
  "access_token": "...",
  "refresh_token": "..."
}
```

### Получение защищённого контента

```bash
curl http://localhost:8000/content/shared \
  -H "Authorization: Bearer <access_token>"
```

### Обновление токенов

```bash
curl -X POST http://localhost:8000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

### Выход

```bash
curl -X POST http://localhost:8000/auth/logout \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

## Технологии

- FastAPI
- Redis
- PyJWT
- Pydantic
- Docker
- Passlib

Co-authored-by: SdvSeven <ssdvseven@gmail.com>
