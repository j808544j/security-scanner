FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/var/lib/gauntlet/scanner.sqlite3 \
    INVENTORY_PATH=/srv/data/inventory.json

WORKDIR /srv/backend
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 scanner \
    && install -d -o scanner -g scanner -m 0750 /var/lib/gauntlet
COPY backend/app ./app
COPY data/inventory.json /srv/data/inventory.json

USER scanner
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).close()"]
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
