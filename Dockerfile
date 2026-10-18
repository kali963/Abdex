# AbdEX application image. Runs as an unprivileged user (SEC-INF-06).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
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
HEALTHCHECK --interval=30s --timeout=6s --start-period=60s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=5).status == 200 else 1)"
ENTRYPOINT ["docker-entrypoint.sh"]
# WEB_CONCURRENCY uvicorn processes (≈ 2 × CPU cores). The client address comes from X-Forwarded-For only
# when TRUST_PROXY=true (behind the reverse proxy); uvicorn's own proxy handling stays off.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-proxy-headers --workers ${WEB_CONCURRENCY:-2} --timeout-keep-alive 30"]
