FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
# официальный модуль подписи Lighter: скачивается с зафиксированного коммита и проверяется по SHA-256
RUN python fetch_signer.py
# работаем не от root; хранилище (и файл с паролем, если он нужен) — в /data, это папка data на сервере
RUN useradd --create-home --uid 10001 guardian && mkdir -p /data && chown guardian /data && chmod 700 /data
USER guardian
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GUARDIAN_VAULT=/data/guardian.vault \
    GUARDIAN_PASSWORD_FILE=/data/password.txt
CMD ["python", "guardian.py"]
