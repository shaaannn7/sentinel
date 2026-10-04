# syntax=docker/dockerfile:1.4

FROM python:3.11-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy alembic and application code
COPY alembic.ini .
COPY alembic/ ./alembic/
COPY app/ ./app/
RUN useradd --create-home --uid 10001 sentinel \
    && chown -R sentinel:sentinel /app
USER sentinel

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]