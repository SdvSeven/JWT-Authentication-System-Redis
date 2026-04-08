#!/usr/bin/env python3
"""
Демонстрационный скрипт для тестирования JWT Auth System.

Запуск:
    python demo.py

Требования:
    - Запущенный сервер (docker-compose up)
    - pip install requests
"""

import requests
import json
from typing import Optional

BASE_URL = "http://localhost:8000"

# Цвета для вывода
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header(text: str):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text:^60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")


def print_step(step: int, text: str):
    print(f"{Colors.YELLOW}[Шаг {step}]{Colors.RESET} {text}")


def print_success(text: str):
    print(f"  {Colors.GREEN}✓ {text}{Colors.RESET}")


def print_error(text: str):
    print(f"  {Colors.RED}✗ {text}{Colors.RESET}")


def print_info(text: str):
    print(f"  {Colors.BLUE}ℹ {text}{Colors.RESET}")


def make_request(
    method: str,
    endpoint: str,
    token: Optional[str] = None,
    data: Optional[dict] = None,
    show_response: bool = True
) -> requests.Response:
    """Выполнение HTTP запроса."""
    url = f"{BASE_URL}{endpoint}"
    headers = {}
    
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    if method == "GET":
        response = requests.get(url, headers=headers)
    elif method == "POST":
        headers["Content-Type"] = "application/json"
        response = requests.post(url, headers=headers, json=data)
    
    if show_response:
        status_color = Colors.GREEN if response.status_code < 400 else Colors.RED
        print(f"  {status_color}[{response.status_code}]{Colors.RESET} {method} {endpoint}")
        
        try:
            body = response.json()
            # Сокращаем вывод токенов
            if "access_token" in body:
                body["access_token"] = body["access_token"][:50] + "..."
            if "refresh_token" in body:
                body["refresh_token"] = body["refresh_token"][:50] + "..."
            print(f"  {json.dumps(body, indent=2, ensure_ascii=False)}\n")
        except:
            print(f"  {response.text[:200]}\n")
    
    return response


def demo():
    """Основная демонстрация."""
    
    print_header("JWT Auth System - Демонстрация")
    
    # Проверка доступности
    print_step(1, "Проверка здоровья сервиса")
    try:
        response = make_request("GET", "/health")
        if response.status_code != 200:
            print_error("Сервер не отвечает. Запустите: docker-compose up")
            return
        print_success("Сервер работает")
    except requests.ConnectionError:
        print_error("Не удалось подключиться к серверу")
        print_info("Запустите: docker-compose up")
        return
    
    # ========== ПУБЛИЧНЫЙ КОНТЕНТ ==========
    print_header("Публичный контент (без авторизации)")
    
    print_step(2, "Получение публичного контента")
    make_request("GET", "/content/public")
    print_success("Публичный контент доступен всем")
    
    # ========== АВТОРИЗАЦИЯ ADMIN ==========
    print_header("Авторизация ADMIN")
    
    print_step(3, "Вход как admin")
    response = make_request("POST", "/auth/login", data={
        "username": "admin",
        "password": "adminpassword123"
    })
    admin_tokens = response.json()
    admin_access = admin_tokens["access_token"]
    admin_refresh = admin_tokens["refresh_token"]
    print_success("Admin авторизован")
    
    # ========== КОНТЕНТ ДЛЯ ADMIN ==========
    print_header("Доступ Admin к контенту")
    
    print_step(4, "Admin -> Общий контент (shared)")
    make_request("GET", "/content/shared", token=admin_access)
    print_success("Admin имеет доступ к shared")
    
    print_step(5, "Admin -> Админ-контент")
    make_request("GET", "/content/admin", token=admin_access)
    print_success("Admin имеет доступ к admin-контенту")
    
    print_step(6, "Admin -> User-контент (должен быть ЗАПРЕЩЁН)")
    response = make_request("GET", "/content/user", token=admin_access)
    if response.status_code == 403:
        print_success("Правильно! Admin НЕ имеет доступа к user-контенту")
        print_info("Это демонстрирует РАЗДЕЛЕНИЕ ролей, а не иерархию")
    
    # ========== АВТОРИЗАЦИЯ USER ==========
    print_header("Авторизация USER")
    
    print_step(7, "Вход как user")
    response = make_request("POST", "/auth/login", data={
        "username": "user",
        "password": "userpassword123"
    })
    user_tokens = response.json()
    user_access = user_tokens["access_token"]
    print_success("User авторизован")
    
    # ========== КОНТЕНТ ДЛЯ USER ==========
    print_header("Доступ User к контенту")
    
    print_step(8, "User -> Общий контент (shared)")
    make_request("GET", "/content/shared", token=user_access)
    print_success("User имеет доступ к shared")
    
    print_step(9, "User -> User-контент")
    make_request("GET", "/content/user", token=user_access)
    print_success("User имеет доступ к user-контенту")
    
    print_step(10, "User -> Админ-контент (должен быть ЗАПРЕЩЁН)")
    response = make_request("GET", "/content/admin", token=user_access)
    if response.status_code == 403:
        print_success("Правильно! User НЕ имеет доступа к admin-контенту")
    
    # ========== REFRESH TOKEN ==========
    print_header("Обновление токенов (Refresh Token Rotation)")
    
    print_step(11, "Обновление токенов admin")
    response = make_request("POST", "/auth/refresh", data={
        "refresh_token": admin_refresh
    })
    if response.status_code == 200:
        new_tokens = response.json()
        print_success("Токены обновлены")
        print_info("Старый refresh token удалён из whitelist")
        print_info("Выдана НОВАЯ пара токенов (Rotation)")
    
    # ========== BLACKLIST ==========
    print_header("Демонстрация Blacklist (logout)")
    
    print_step(12, "Logout admin (токен в blacklist)")
    old_admin_access = admin_access
    make_request("POST", "/auth/logout", token=admin_access, data={
        "refresh_token": admin_refresh
    })
    print_success("Logout выполнен")
    
    print_step(13, "Попытка использовать старый токен")
    response = make_request("GET", "/content/shared", token=old_admin_access)
    if response.status_code == 401:
        print_success("Токен в blacklist - доступ запрещён!")
    
    # ========== РЕГИСТРАЦИЯ ==========
    print_header("Регистрация нового пользователя")
    
    print_step(14, "Регистрация testuser")
    response = make_request("POST", "/auth/register", data={
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword123",
        "role": "user"
    })
    if response.status_code == 201:
        print_success("Пользователь зарегистрирован")
    elif response.status_code == 409:
        print_info("Пользователь уже существует (повторный запуск демо)")
    
    # ========== ИТОГИ ==========
    print_header("Демонстрация завершена")
    
    print(f"""
{Colors.GREEN}Что было продемонстрировано:{Colors.RESET}

  ✓ JWT аутентификация (Access + Refresh токены)
  ✓ Whitelist для refresh токенов в Redis
  ✓ Blacklist для отозванных access токенов
  ✓ Refresh Token Rotation (защита от replay attack)
  ✓ Ролевой доступ к контенту:
    • Публичный контент - всем
    • Общий контент (shared) - USER и ADMIN
    • Админ-контент - только ADMIN
    • User-контент - только USER
  ✓ Rate limiting
  ✓ Device fingerprinting

{Colors.CYAN}Документация API:{Colors.RESET} http://localhost:8000/docs
{Colors.CYAN}Redis UI:{Colors.RESET} docker-compose --profile debug up (порт 8081)
    """)


if __name__ == "__main__":
    demo()
