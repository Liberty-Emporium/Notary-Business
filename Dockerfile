FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . .

# Create data directory (overridden by Railway volume mount)
RUN mkdir -p /data

# Default port (Railway overrides with $PORT env var)
ENV PORT=5000
EXPOSE 5000

# Start — shell form expands $PORT at runtime
CMD gunicorn app:app --bind 0.0.0.0:$PORT --workers 2
