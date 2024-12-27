# Dockerfile
FROM python:3.11-slim

# 1) Use the official Playwright + Python base
FROM mcr.microsoft.com/playwright/python:v1.35.0-focal

# 2) Download & install subfinder (pick a currently available version)
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip -O subfinder.zip \
    && unzip subfinder.zip \
    && mv subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm subfinder.zip

WORKDIR /app

# 3) Copy requirements & install Python deps
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# 4) Install Playwright’s browsers (Chromium)
RUN playwright install --with-deps chromium

# 5) Copy the rest of your app code
COPY . /app

# Expose port 8000 for Flask/gunicorn
EXPOSE 8000

# Default command: run gunicorn on port 8000
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
