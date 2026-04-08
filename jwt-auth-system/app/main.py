"""
JWT Authentication System с Redis.

Основной файл приложения FastAPI.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.services.redis_service import redis_service
from app.api.routes import auth, content

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle: проверка подключения к Redis при старте."""
    # Startup
    if not redis_service.health_check():
        print("WARNING: Redis не доступен!")
    else:
        print("✅ Redis подключён")
    
    yield
    
    # Shutdown
    print("Приложение завершается")


app = FastAPI(
    title=settings.APP_NAME,
    description="""
## JWT Authentication System с Redis

Система аутентификации и авторизации с использованием:
- **JWT токены** (Access + Refresh)
- **Redis** для whitelist/blacklist
- **Ролевой доступ** (ADMIN, USER)

### Особенности:
- Whitelist для refresh токенов
- Blacklist для отозванных access токенов  
- Refresh Token Rotation
- Device Fingerprinting
- Rate Limiting
- Обнаружение аномалий

### Тестовые пользователи:
- **admin** / adminpassword123 (роль: ADMIN)
- **user** / userpassword123 (роль: USER)
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене указать конкретные домены
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Глобальная обработка ошибок
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Глобальный обработчик ошибок."""
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Внутренняя ошибка сервера",
            "error": str(exc) if settings.DEBUG else None
        }
    )


# Подключение роутов
app.include_router(auth.router)
app.include_router(content.router)


@app.get("/", tags=["Health"])
async def root():
    """Корневой endpoint."""
    return {
        "service": settings.APP_NAME,
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """
    Проверка здоровья сервиса.
    
    Проверяет:
    - Доступность Redis
    """
    redis_ok = redis_service.health_check()
    
    status = "healthy" if redis_ok else "degraded"
    
    return {
        "status": status,
        "redis": "connected" if redis_ok else "disconnected"
    }
