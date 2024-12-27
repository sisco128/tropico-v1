# subdomain_discovery.py
import subprocess
import json

def run_subfinder(domain):
    """
    Runs subfinder and returns a list of discovered subdomains.
    Subfinder must be in PATH (/usr/local/bin/subfinder).
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
                host = data.get("host")
                if host:
                    subdomains.append(host)
        return subdomains

    except Exception as e:
        print(f"Exception in run_subfinder: {e}")
        return []
