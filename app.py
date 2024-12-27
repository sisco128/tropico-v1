# app.py
from flask import Flask, request, jsonify
from redis import Redis
from rq import Queue
import os

from db import init_db, create_scan, get_scan
from tasks import discover_subdomains_and_endpoints

app = Flask(__name__)

# Initialize DB (creates tables if needed)
init_db()

# Configure Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_conn = Redis.from_url(REDIS_URL)
q = Queue("default", connection=redis_conn)

@app.route("/scans", methods=["POST"])
def create_scan_api():
    data = request.get_json()
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "domain is required"}), 400

    # 1) Insert a new 'scan' row
    scan_id = create_scan(domain)
    # 2) Enqueue the new combined job
    job = q.enqueue(discover_subdomains_and_endpoints, scan_id, domain)
    return jsonify({"scan_id": scan_id, "job_id": job.get_id()}), 201

@app.route("/scans/<int:scan_id>", methods=["GET"])
def get_scan_api(scan_id):
    scan_data = get_scan(scan_id)
    if not scan_data:
        return jsonify({"error": "Not found"}), 404
    return jsonify(scan_data)

if __name__ == "__main__":
    # For local dev run:
    # python app.py
    app.run(host="0.0.0.0", port=8000, debug=True)
