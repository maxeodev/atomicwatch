FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 4 adm 2>/dev/null || true && \
    groupadd -g 1001 atomicwatch && \
    useradd -u 1001 -g 1001 -G 4 -s /sbin/nologin -d /app atomicwatch

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER 1001
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
