# Base Image
FROM mcr.microsoft.com/playwright/python:v1.35.0-focal

# Install packages needed for Subfinder and Python
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Subfinder
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip -O subfinder.zip \
    && unzip subfinder.zip \
    && mv subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm subfinder.zip

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install --with-deps chromium

# Copy the rest of the application
COPY . /app

# Expose port 10000 for Flask app
EXPOSE 10000

# Default command to run the Flask app
CMD ["gunicorn", "-b", "0.0.0.0:10000", "app:app"]
