FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create necessary directories
RUN mkdir -p Logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV OPENAI_API_KEY=${OPENAI_API_KEY}

# Command to run the application
CMD ["python", "main.py"] 