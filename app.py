from flask import Flask, request, jsonify
from redis import Redis
from rq import Queue
import os
import uuid

from db import init_db, create_account, create_domain, create_scan, get_scan, get_endpoint_details
from tasks import discover_subdomains_and_endpoints

app = Flask(__name__)

# Initialize DB (creates tables if needed)
init_db()

# Configure Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_conn = Redis.from_url(REDIS_URL)
q = Queue("default", connection=redis_conn)

@app.route("/account", methods=["POST"])
def create_account_api():
    data = request.get_json()
    account_name = data.get("account_name")
    if not account_name:
        return jsonify({"error": "account_name is required"}), 400
    
    account_uid = str(uuid.uuid4())
    create_account(account_uid, account_name)
    return jsonify({"account_uid": account_uid}), 201

@app.route("/account/<account_uid>/domain", methods=["POST"])
def create_domain_api(account_uid):
    data = request.get_json()
    domain_name = data.get("domain_name")
    if not domain_name:
        return jsonify({"error": "domain_name is required"}), 400

    domain_uid = str(uuid.uuid4())
    create_domain(account_uid, domain_uid, domain_name)
    return jsonify({"domain_uid": domain_uid}), 201

@app.route("/account/<account_uid>/domain/<domain_uid>/scan", methods=["POST"])
def create_scan_api(account_uid, domain_uid):
    scan_uid = str(uuid.uuid4())
    create_scan(account_uid, domain_uid, scan_uid)

    # Enqueue the combined subdomain, endpoint discovery, and ZAP scan job
    job = q.enqueue(discover_subdomains_and_endpoints, scan_uid, domain_uid)
    return jsonify({"scan_uid": scan_uid, "job_id": job.get_id()}), 201

@app.route("/account/<account_uid>/domain/<domain_uid>/scan/<scan_uid>", methods=["GET"])
def get_scan_results_api(account_uid, domain_uid, scan_uid):
    scan_data = get_scan(scan_uid)
    if not scan_data:
        return jsonify({"error": "Not found"}), 404
    return jsonify(scan_data)

@app.route("/account/<account_uid>/endpoint/<endpoint_uid>", methods=["GET"])
def get_endpoint_details_api(account_uid, endpoint_uid):
    endpoint_data = get_endpoint_details(endpoint_uid)
    if not endpoint_data:
        return jsonify({"error": "Not found"}), 404
    return jsonify(endpoint_data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)
