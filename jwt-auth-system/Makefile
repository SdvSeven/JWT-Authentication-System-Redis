.PHONY: help build up down logs shell test demo clean

# Цвета
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RESET  := \033[0m

help: ## Показать справку
	@echo "$(GREEN)JWT Auth System - Команды$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}'

build: ## Собрать Docker образы
	docker-compose build

up: ## Запустить сервисы
	docker-compose up -d
	@echo "$(GREEN)API запущен на http://localhost:8000$(RESET)"
	@echo "$(GREEN)Документация: http://localhost:8000/docs$(RESET)"

up-debug: ## Запустить с Redis UI
	docker-compose --profile debug up -d
	@echo "$(GREEN)Redis UI: http://localhost:8081$(RESET)"

down: ## Остановить сервисы
	docker-compose down

down-v: ## Остановить и удалить volumes
	docker-compose down -v

logs: ## Показать логи
	docker-compose logs -f

logs-api: ## Логи только API
	docker-compose logs -f api

shell: ## Shell в контейнере API
	docker-compose exec api /bin/bash

redis-cli: ## Redis CLI
	docker-compose exec redis redis-cli

test: ## Запустить тесты
	pip install pytest httpx --quiet
	pytest tests/ -v

demo: ## Запустить демонстрацию
	@pip install requests --quiet 2>/dev/null || true
	@python demo.py

clean: ## Очистить Docker ресурсы
	docker-compose down -v --rmi local
	docker system prune -f

# Разработка
dev: ## Запустить для разработки (без Docker)
	pip install -r requirements.txt
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

lint: ## Проверка кода
	pip install ruff --quiet
	ruff check app/

format: ## Форматирование кода
	pip install ruff --quiet
	ruff format app/
