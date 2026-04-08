# JWT Auth System - Production Dockerfile
# Multi-stage build для оптимизации размера образа

# Этап 1: Базовый образ с зависимостями
FROM python:3.12-slim as base

# Переменные окружения
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*


# Этап 2: Builder для установки зависимостей
FROM base as builder

# Создаём пользователя
RUN useradd -m -u 1000 appuser

# Переключаемся на пользователя
USER appuser

COPY requirements.txt .
RUN pip install --user --no-warn-script-location -r requirements.txt


# Этап 3: Production образ
FROM base as production

# Копируем установленные пакеты
COPY --from=builder --chown=appuser:appuser /home/appuser/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH

# Копируем код приложения
COPY --chown=appuser:appuser ./app ./app

# Создаём пользователя
RUN useradd -m -u 1000 appuser

USER appuser

# Порт приложения
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Запуск приложения
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
