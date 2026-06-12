FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . .

# Create data directory (will be overridden by Railway volume mount)
RUN mkdir -p /data

# Expose port
EXPOSE 5000

# Run
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--workers", "2"]
