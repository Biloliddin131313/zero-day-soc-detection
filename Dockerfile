FROM python:3.12-slim

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.docker.txt .
RUN pip install --no-cache-dir -r requirements.docker.txt

# Copy application code
COPY database/ ./database/
COPY dashboard/ ./dashboard/
COPY scripts/ ./scripts/
COPY models/ ./models/
COPY dataset/ ./dataset/

# Create DB if not exists
RUN python3 database/init_db.py 2>/dev/null || true

EXPOSE 5000 8001
