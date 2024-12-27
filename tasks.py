# tasks.py
from db import insert_subdomain, update_scan_status, insert_endpoint
from subdomain_discovery import run_subfinder

from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin

def discover_subdomains(scan_id, domain):
    """
    1) Subfinder for subdomains
    2) For each subdomain -> discover endpoints -> analyze -> store in DB
    3) Mark 'complete' or 'error'
    """
    try:
        # 1) Subdomain discovery
        subdomains = run_subfinder(domain)
        for sd in subdomains:
            insert_subdomain(scan_id, sd)

        # 2) For each subdomain, discover & analyze endpoints
        for subd in subdomains:
            discovered_urls = discover_endpoints(subd)
            for url in discovered_urls:
                ep_data = analyze_api(url)
                if ep_data:
                    insert_endpoint(scan_id, subd, ep_data)

        # 3) Mark completed
        update_scan_status(scan_id, 'complete')

    except Exception as e:
        print(f"Error in discover_subdomains: {e}")
        update_scan_status(scan_id, 'error')


def discover_endpoints(subdomain):
    """
    Use Playwright + BeautifulSoup to gather all 'href' and 'src' from <a> and <script>.
    Returns a list of absolute URLs.
    """
    discovered_urls = []
    url = f"https://{subdomain}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            try:
                page.goto(url, timeout=5000)
            except Exception as e:
                print(f"Error loading page {url}: {e}")
                browser.close()
                return []

            soup = BeautifulSoup(page.content(), "html.parser")
            links = [a.get("href") for a in soup.find_all("a", href=True)]
            scripts = [s.get("src") for s in soup.find_all("script", src=True)]

            all_urls = []
            for link in links + scripts:
                if link:
                    full_url = urljoin(url, link)
                    all_urls.append(full_url)

            discovered_urls = list(set(all_urls))
            browser.close()
    except Exception as e:
        print(f"Error discovering endpoints on {subdomain}: {e}")

    return discovered_urls

def analyze_api(url):
    """
    Makes a GET request to the URL, returns basic info as dict or None if failed.
    """
    try:
        r = requests.get(url, timeout=5)
        return {
            "url": url,
            "status_code": r.status_code,
            "content_type": r.headers.get("Content-Type", "Unknown"),
            "server": r.headers.get("Server", "Unknown"),
            "framework": "Unknown",
        }
    except Exception as e:
        print(f"Error analyzing URL {url}: {e}")
        return None
