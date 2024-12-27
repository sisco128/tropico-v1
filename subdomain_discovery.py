# subdomain_discovery.py
import subprocess
import json

def run_subfinder(domain):
    """
    Runs subfinder and returns a list of discovered subdomains.
    Expects subfinder in PATH. Example:
        subfinder -d example.com -oJ
    """
    try:
        cmd = ["subfinder", "-d", domain, "-oJ"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running subfinder: {result.stderr}")
            return []

        subdomains = []
        for line in result.stdout.splitlines():
            if line.strip():
                data = json.loads(line)
                subdomains.append(data["host"])
        return subdomains

    except Exception as e:
        print(f"Exception in run_subfinder: {e}")
        return []
