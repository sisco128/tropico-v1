import os
import requests
from db import insert_subdomain, update_scan_status, insert_endpoint, insert_alert
from subdomain_discovery import run_subfinder
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from urllib.parse import urljoin

ZAP_API_KEY = os.getenv("ZAP_API_KEY")  # Fetch from environment variable
ZAP_BASE_URL = "http://zap-service:8080"

def discover_subdomains_and_endpoints(scan_id, domain_uid):
    """
    Combines subdomain discovery, endpoint discovery, and ZAP passive scanning.
    """
    try:
        # Subdomain discovery
        subdomains = run_subfinder(domain_uid)
        for sd in subdomains:
            insert_subdomain(scan_id, sd)

        # Endpoint discovery
        for subdomain in subdomains:
            discovered_urls = discover_endpoints(subdomain)
            for url in discovered_urls:
                ep_data = analyze_api(url)
                if ep_data:
                    endpoint_id = insert_endpoint(scan_id, subdomain, ep_data)
                    run_zap_scan(endpoint_id, url)

        # Mark scan as complete
        update_scan_status(scan_id, "complete")

    except Exception as e:
        print(f"Error in discover_subdomains_and_endpoints: {e}")
        update_scan_status(scan_id, "error")


def discover_endpoints(subdomain):
    """
    Use Playwright and BeautifulSoup to discover endpoints from subdomains.
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

            for link in links + scripts:
                if link:
                    discovered_urls.append(urljoin(url, link))

            discovered_urls = list(set(discovered_urls))
            browser.close()
    except Exception as e:
        print(f"Error discovering endpoints on {subdomain}: {e}")
    return discovered_urls


def analyze_api(url):
    """
    Perform basic analysis of the given URL.
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


def run_zap_scan(endpoint_id, url):
    """
    Starts a ZAP passive scan for the given URL and logs alerts.
    """
    try:
        # Start ZAP Spider
        response = requests.get(
            f"{ZAP_BASE_URL}/JSON/spider/action/scan/",
            params={"apikey": ZAP_API_KEY, "url": url, "maxChildren": 10},
        )
        response.raise_for_status()
        scan_id = response.json().get("scan")
        if not scan_id:
            print(f"Failed to start ZAP Spider for {url}")
            return

        # Poll Spider Status
        while True:
            status_response = requests.get(
                f"{ZAP_BASE_URL}/JSON/spider/view/status/",
                params={"apikey": ZAP_API_KEY, "scanId": scan_id},
            )
            status_response.raise_for_status()
            if status_response.json().get("status") == "100":
                break

        # Retrieve Alerts
        alerts_response = requests.get(
            f"{ZAP_BASE_URL}/JSON/core/view/alerts/",
            params={"apikey": ZAP_API_KEY, "baseurl": url},
        )
        alerts_response.raise_for_status()
        alerts = alerts_response.json().get("alerts", [])
        for alert in alerts:
            insert_alert(endpoint_id, alert)
    except Exception as e:
        print(f"Error running ZAP scan on {url}: {e}")
