import os
import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from urllib.parse import urljoin

from db import (
    insert_alert,
    insert_subdomain,
    update_scan_status,
    insert_endpoint,
    get_domain_name_by_uid,
    get_scan_id_by_uid
)
from subdomain_discovery import run_subfinder

ZAP_API_KEY = os.getenv("ZAP_API_KEY")
ZAP_BASE_URL = os.getenv("ZAP_BASE_URL")

def discover_subdomains_and_endpoints(scan_uid, domain_uid):
    """
    Combines subdomain discovery, endpoint discovery, and ZAP passive scanning.
    This function uses the *UUID* for scan_uid, then looks up the integer PK.
    Likewise, it looks up the domain_name from the domain UID.
    """
    try:
        # Mark scan as "in_progress"
        update_scan_status(scan_uid, "in_progress")

        # Convert the scan UID to the integer scans.id
        scan_pk = get_scan_id_by_uid(scan_uid)
        if not scan_pk:
            raise ValueError(f"Scan UID={scan_uid} not found in DB.")

        # Get the actual domain name from the domain UID
        domain_name = get_domain_name_by_uid(domain_uid)
        if not domain_name:
            raise ValueError(f"Domain UID={domain_uid} not found in DB.")

        # Subdomain discovery
        subdomains = run_subfinder(domain_name)  # Pass the real domain name
        for subdomain in subdomains:
            insert_subdomain(scan_pk, subdomain)  # Insert with integer PK

        # Endpoint discovery for each subdomain
        for subdomain in subdomains:
            discovered_urls = discover_endpoints(subdomain)
            for url in discovered_urls:
                ep_data = analyze_api(url)
                if ep_data:
                    endpoint_id = insert_endpoint(scan_pk, subdomain, ep_data)
                    run_zap_scan(endpoint_id, url)

        # Mark scan as complete
        update_scan_status(scan_uid, "complete")

    except Exception as e:
        print(f"Error in discover_subdomains_and_endpoints: {e}")
        # Mark the scan as failed (error)
        update_scan_status(scan_uid, "error")

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

            # Grab the HTML content and parse
            soup = BeautifulSoup(page.content(), "html.parser")

            # Collect all links from <a href="...">
            links = [a.get("href") for a in soup.find_all("a", href=True)]
            # Collect all script sources from <script src="...">
            scripts = [s.get("src") for s in soup.find_all("script", src=True)]

            for link in links + scripts:
                if link:
                    # Normalize to absolute URL
                    full_url = urljoin(url, link)
                    discovered_urls.append(full_url)

            discovered_urls = list(set(discovered_urls))  # Remove duplicates
            browser.close()
    except Exception as e:
        print(f"Error discovering endpoints on {subdomain}: {e}")

    return discovered_urls

def analyze_api(url):
    """
    Perform basic analysis (status code, headers, etc.) of the given URL.
    """
    try:
        r = requests.get(url, timeout=5)
        return {
            "url": url,
            "status_code": r.status_code,
            "content_type": r.headers.get("Content-Type", "Unknown"),
            "server": r.headers.get("Server", "Unknown"),
            "framework": "Unknown",  # You could do more analysis if needed
        }
    except Exception as e:
        print(f"Error analyzing URL {url}: {e}")
        return None

def run_zap_scan(endpoint_id, url):
    """
    Performs a ZAP spider scan on the given URL, then collects any alerts.
    endpoint_id is the integer PK of the endpoints row.
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

        # Poll Spider Status until it's 100%
        while True:
            status_response = requests.get(
                f"{ZAP_BASE_URL}/JSON/spider/view/status/",
                params={"apikey": ZAP_API_KEY, "scanId": scan_id},
            )
            status_response.raise_for_status()
            if status_response.json().get("status") == "100":
                break

        # Retrieve ZAP Alerts
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
