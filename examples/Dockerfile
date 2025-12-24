# Use Python 3.11 slim image
FROM python:3.11-slim

# Install git (needed for pip install from GitHub)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install gunicorn for production server
RUN pip install --no-cache-dir gunicorn

# Copy application files
COPY app.py .

# Expose port 8080 (Cloud Run requirement)
EXPOSE 8080

# Run the application with gunicorn
# Use PORT environment variable (Cloud Run provides this)
# Configure gunicorn logging to stdout for Cloud Run
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 \
    --access-logfile - --error-logfile - \
    --log-level info \
    app:app
