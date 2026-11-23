FROM python:3.13-alpine

# Patch OS packages first: the image scan rejects a final stage with
# unpatched Alpine libraries, and a cached layer would keep the old ones.
RUN echo "os-refresh 2026-11-23" && apk upgrade --no-cache

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000 \
    FORGECORE_HOME=/data

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY forgecore ./forgecore
COPY main.py ./

# Unprivileged runtime user. Only its own data directory is writable.
RUN adduser -D -u 10001 -h /app forgecore \
    && mkdir -p /data \
    && chown -R forgecore:forgecore /data \
    && chmod 0700 /data

USER forgecore

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

CMD ["python", "-m", "forgecore", "serve", "--host", "0.0.0.0"]
