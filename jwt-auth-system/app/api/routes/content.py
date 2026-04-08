"""
API роуты для контента с ролевым доступом.

Демонстрирует систему ролей:
- /content/public - доступен всем (без авторизации)
- /content/shared - доступен авторизованным (USER и ADMIN)
- /content/admin - доступен только ADMIN
- /content/user - доступен только USER

Структура соответствует заданию:
- Общий контент (shared) для обеих ролей
- Эксклюзивный контент для каждой роли
"""

from fastapi import APIRouter, Depends

from app.models.schemas import Role, ContentResponse, ContentItem, UserInDB
from app.api.dependencies import get_current_user, require_role

router = APIRouter(prefix="/content", tags=["Content"])


# Имитация базы контента
CONTENT_DB = {
    "public": [
        ContentItem(
            id="pub-1",
            title="Добро пожаловать",
            content="Это публичный контент, доступный всем посетителям.",
            access_level="public"
        ),
        ContentItem(
            id="pub-2",
            title="О нашей системе",
            content="JWT авторизация с Redis для whitelist/blacklist токенов.",
            access_level="public"
        ),
    ],
    "shared": [
        ContentItem(
            id="shared-1",
            title="Общий ресурс",
            content="Этот контент доступен всем авторизованным пользователям: и USER, и ADMIN.",
            access_level="shared"
        ),
        ContentItem(
            id="shared-2",
            title="Документация API",
            content="Полная документация доступна авторизованным пользователям.",
            access_level="shared"
        ),
        ContentItem(
            id="shared-3",
            title="Правила использования",
            content="Общие правила для всех авторизованных пользователей системы.",
            access_level="shared"
        ),
    ],
    "admin": [
        ContentItem(
            id="admin-1",
            title="Панель администратора",
            content="Эксклюзивный контент для администраторов. Управление пользователями.",
            access_level="admin"
        ),
        ContentItem(
            id="admin-2",
            title="Системные логи",
            content="Доступ к логам системы и статистике.",
            access_level="admin"
        ),
        ContentItem(
            id="admin-3",
            title="Настройки безопасности",
            content="Конфигурация JWT, Redis, rate limiting.",
            access_level="admin"
        ),
    ],
    "user": [
        ContentItem(
            id="user-1",
            title="Личный кабинет",
            content="Эксклюзивный контент для обычных пользователей.",
            access_level="user"
        ),
        ContentItem(
            id="user-2",
            title="Мои данные",
            content="Управление персональными данными пользователя.",
            access_level="user"
        ),
        ContentItem(
            id="user-3",
            title="Подписки",
            content="Управление подписками и уведомлениями.",
            access_level="user"
        ),
    ],
}


@router.get("/public", response_model=ContentResponse)
async def get_public_content():
    """
    Публичный контент.
    
    Доступен всем без авторизации.
    """
    return ContentResponse(
        items=CONTENT_DB["public"],
        user_role=None
    )


@router.get("/shared", response_model=ContentResponse)
async def get_shared_content(
    current_user: UserInDB = Depends(require_role(Role.ADMIN, Role.USER))
):
    """
    Общий контент для авторизованных пользователей.
    
    Доступен обеим ролям: USER и ADMIN.
    Демонстрирует общий ресурс между ролями.
    """
    return ContentResponse(
        items=CONTENT_DB["shared"],
        user_role=current_user.role
    )


@router.get("/admin", response_model=ContentResponse)
async def get_admin_content(
    current_user: UserInDB = Depends(require_role(Role.ADMIN))
):
    """
    Эксклюзивный контент для администраторов.
    
    Доступен ТОЛЬКО роли ADMIN.
    Демонстрирует контент, принадлежащий только одной роли.
    """
    return ContentResponse(
        items=CONTENT_DB["admin"],
        user_role=current_user.role
    )


@router.get("/user", response_model=ContentResponse)
async def get_user_content(
    current_user: UserInDB = Depends(require_role(Role.USER))
):
    """
    Эксклюзивный контент для пользователей.
    
    Доступен ТОЛЬКО роли USER.
    Демонстрирует контент, принадлежащий только одной роли.
    
    Важно: ADMIN НЕ имеет доступа к этому контенту,
    что демонстрирует разделение ролей (не иерархию).
    """
    return ContentResponse(
        items=CONTENT_DB["user"],
        user_role=current_user.role
    )


@router.get("/my", response_model=ContentResponse)
async def get_my_content(
    current_user: UserInDB = Depends(get_current_user)
):
    """
    Контент текущего пользователя.
    
    Автоматически возвращает:
    - Общий контент (shared)
    - Эксклюзивный контент для роли пользователя
    """
    items = CONTENT_DB["shared"].copy()
    
    if current_user.role == Role.ADMIN:
        items.extend(CONTENT_DB["admin"])
    elif current_user.role == Role.USER:
        items.extend(CONTENT_DB["user"])
    
    return ContentResponse(
        items=items,
        user_role=current_user.role
    )
