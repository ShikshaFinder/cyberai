FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    git \
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
ENV PYTHONPATH=/app
ENV AZURE_OPENAI_API_KEY=${AZURE_OPENAI_API_KEY}
ENV AZURE_OPENAI_ENDPOINT=${AZURE_OPENAI_ENDPOINT}
ENV AZURE_OPENAI_DEPLOYMENT_NAME=${AZURE_OPENAI_DEPLOYMENT_NAME}
ENV AGENT_NAME=${AGENT_NAME}

# Command to run the application
CMD ["python", "main.py"] 