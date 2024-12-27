# tasks.py
from subdomain_discovery import run_subfinder
from db import insert_subdomain, update_scan_status

def discover_subdomains(scan_id, domain):
    """
    Runs subfinder, inserts subdomains, and updates the scan status.
    """
    try:
        subdomains = run_subfinder(domain)
        for sd in subdomains:
            insert_subdomain(scan_id, sd)
        update_scan_status(scan_id, 'complete')
    except Exception as e:
        print(f"Error in discover_subdomains: {e}")
        update_scan_status(scan_id, 'error')
