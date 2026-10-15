# AbdEX application image. Runs as an unprivileged user (SEC-INF-06).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN useradd --system --uid 10001 --home /app abdex \
    && mkdir -p /data/storage && chown -R abdex /data \
    && chmod +x /usr/local/bin/docker-entrypoint.sh
USER abdex

EXPOSE 8000
ENTRYPOINT ["docker-entrypoint.sh"]
# Client IP comes from X-Forwarded-For only when TRUST_PROXY=true (set it behind your reverse proxy).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
