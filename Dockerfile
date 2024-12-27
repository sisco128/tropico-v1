# Dockerfile
FROM python:3.11-slim

# 1) Install system packages needed for subfinder & building + headless chromium for Playwright
RUN apt-get update && apt-get install -y \
    wget unzip ca-certificates fonts-liberation \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2 libpangocairo-1.0-0 libxshmfence1 libx11-6 libx11-xcb1 libxcb1 \
    libxcomposite1 libxcursor1 libxdamage1 libxi6 libxtst6 libxslt1.1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# 2) Download & install subfinder (pick a currently available version)
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.10.5/subfinder_2.10.5_linux_amd64.zip -O subfinder.zip \
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
