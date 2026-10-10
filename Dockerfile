FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY gateshield ./gateshield
COPY migrations ./migrations
COPY alembic.ini ./
RUN pip install --no-cache-dir . && \
    groupadd --system gateshield && useradd --system --gid gateshield --home-dir /app gateshield && \
    chown -R gateshield:gateshield /app

USER gateshield
EXPOSE 8000
STOPSIGNAL SIGTERM
CMD ["uvicorn", "gateshield.app:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "30"]
