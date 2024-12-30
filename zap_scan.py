import requests
import os
from db import insert_alert

ZAP_API_KEY = os.getenv("ZAP_API_KEY")
ZAP_BASE_URL = os.getenv("ZAP_BASE_URL", "http://localhost:8080")

def start_passive_scan(target_url):
    """
    Initiates a Passive Scan for a target URL using ZAP.
    """
    try:
        print(f"[+] Starting Passive Scan for {target_url}")
        response = requests.get(
            f"{ZAP_BASE_URL}/JSON/core/action/scan/",
            params={"apikey": ZAP_API_KEY, "url": target_url},
            timeout=10,
        )
        response.raise_for_status()
        return response.json().get("scan")
    except Exception as e:
        print(f"[-] Error starting Passive Scan: {e}")
        return None

def poll_passive_scan_status(scan_id):
    """
    Polls the Passive Scan status until it is complete.
    """
    while True:
        try:
            response = requests.get(
                f"{ZAP_BASE_URL}/JSON/core/view/status/",
                params={"apikey": ZAP_API_KEY, "scanId": scan_id},
                timeout=10,
            )
            response.raise_for_status()
            status = int(response.json().get("status", 0))
            print(f"[+] Passive Scan progress: {status}%")
            if status >= 100:
                break
        except Exception as e:
            print(f"[-] Error polling Passive Scan status: {e}")
            break

def get_alerts(endpoint_uid, target_url):
    """
    Retrieves alerts for a target URL and stores them in the database.
    """
    try:
        print(f"[+] Fetching alerts for {target_url}")
        response = requests.get(
            f"{ZAP_BASE_URL}/JSON/core/view/alerts/",
            params={"apikey": ZAP_API_KEY, "baseurl": target_url},
            timeout=10,
        )
        response.raise_for_status()
        alerts = response.json().get("alerts", [])
        for alert in alerts:
            insert_alert(endpoint_uid, alert)
    except Exception as e:
        print(f"[-] Error retrieving alerts: {e}")
