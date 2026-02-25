FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

# On installe le C (gcc), OpenSSL (libssl-dev) ET le compilateur Rust (cargo, rustc)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    python3-dev \
    pkg-config \
    libssl-dev \
    cargo \
    rustc \
    && pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove gcc libffi-dev python3-dev pkg-config libssl-dev cargo rustc \
    && rm -rf /var/lib/apt/lists/*

COPY main.py .
COPY static/ static/

RUN mkdir -p /app/data

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
