FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    dnsutils \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY risk_meter.py .

RUN mkdir -p /app/input /app/output

RUN chmod +x risk_meter.py

ENTRYPOINT ["python3", "risk_meter.py"]
