# Base Image
FROM mcr.microsoft.com/playwright/python:v1.35.0-focal

# Install packages needed for ZAP, Subfinder, and Python
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    openjdk-11-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Install ZAP
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.12.0/ZAP_2_12_0_unix.sh \
    && chmod +x ZAP_2_12_0_unix.sh \
    && ./ZAP_2_12_0_unix.sh -q -dir /zap \
    && rm ZAP_2_12_0_unix.sh

# Install Subfinder
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip -O subfinder.zip \
    && unzip subfinder.zip \
    && mv subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm subfinder.zip

# Working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install --with-deps chromium

# Copy the rest of the application
COPY . /app

# Expose port 8000 for Flask app
EXPOSE 8000

# Expose port 8080 for ZAP API
EXPOSE 8080

# Start ZAP as a background process and Flask app using Gunicorn
CMD ["/bin/bash", "-c", "/zap/zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=your_zap_api_key & gunicorn -b 0.0.0.0:8000 app:app"]
