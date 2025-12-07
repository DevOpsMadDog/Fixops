FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory
RUN mkdir -p /app/.fixops_data

# Expose port
EXPOSE 8000

# Set environment variables
ENV FIXOPS_MODE=demo
ENV FIXOPS_DATA_DIR=/app/.fixops_data
ENV FIXOPS_API_TOKEN=demo-token-12345
ENV PYTHONUNBUFFERED=1

# Run the API
CMD ["uvicorn", "apps.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
