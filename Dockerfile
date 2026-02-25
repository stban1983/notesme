FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    python3-dev \
    && pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove gcc libffi-dev python3-dev \
    && rm -rf /var/lib/apt/lists/*


COPY main.py .
COPY static/ static/

RUN mkdir -p /app/data

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
