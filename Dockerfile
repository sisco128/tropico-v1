# Dockerfile
FROM python:3.11-slim

# 1) Install packages needed for subfinder & building
RUN apt-get update && apt-get install -y wget unzip && rm -rf /var/lib/apt/lists/*

# 2) Download & install subfinder (use a currently available version)
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip -O subfinder.zip \
    && unzip subfinder.zip \
    && mv subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm subfinder.zip

# 3) Create a working directory
WORKDIR /app

# 4) Copy requirements and install Python libs, including gunicorn
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

# 5) Copy the rest of your app code
COPY . /app

# 6) Expose port 8000 (Flask default)
EXPOSE 8000

# 7) Default command: runs the Flask app with gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
