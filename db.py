import os
import psycopg2
from psycopg2.extras import RealDictCursor
import uuid
import json

def get_connection():
    """
    Connect to Postgres using DATABASE_URL or fallback DSN with 'localhost'.
    """
    db_url = os.getenv("DATABASE_URL") or "postgres://siscolo:@localhost:5432/my_local_db"
    return psycopg2.connect(db_url)

def init_db():
    """
    Create the tables if they don't exist.
    """
    conn = get_connection()
    cur = conn.cursor()

    # Enable the pgcrypto extension for gen_random_uuid()
    cur.execute("""
        CREATE EXTENSION IF NOT EXISTS pgcrypto;
    """)

    # accounts table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            uid UUID NOT NULL DEFAULT gen_random_uuid(),
            account_name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    # domains table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id SERIAL PRIMARY KEY,
            account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            uid UUID NOT NULL DEFAULT gen_random_uuid(),
            domain_name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    # scans table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            uid UUID NOT NULL DEFAULT gen_random_uuid(),
            status VARCHAR(20) NOT NULL DEFAULT 'queued',
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    # subdomains table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            subdomain VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    # endpoints table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            uid UUID NOT NULL DEFAULT gen_random_uuid(),
            subdomain VARCHAR(255) NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER,
            content_type VARCHAR(255),
            server VARCHAR(255),
            framework VARCHAR(255),
            alerts UUID[] DEFAULT ARRAY[]::UUID[],
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    # alerts table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            url TEXT NOT NULL,
            method VARCHAR(10) DEFAULT 'GET',
            parameter VARCHAR(255),
            attack TEXT,
            evidence TEXT,
            other_info TEXT,
            instances INTEGER DEFAULT 1,
            solution TEXT,
            references_list TEXT[],
            severity VARCHAR(50),
            cwe_id VARCHAR(50),
            wasc_id VARCHAR(50),
            plugin_id VARCHAR(50),
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    conn.commit()
    cur.close()
    conn.close()

def create_account(uid, account_name):
    """
    Insert a new account into the 'accounts' table.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO accounts (uid, account_name) VALUES (%s, %s);
    """, (uid, account_name))
    conn.commit()
    cur.close()
    conn.close()

def create_domain(account_uid, domain_uid, domain_name):
    """
    Insert a new domain into the 'domains' table.
    """
    conn = get_connection()
    cur = conn.cursor()

    # Get the account ID from the UID
    cur.execute("SELECT id FROM accounts WHERE uid = %s;", (account_uid,))
    account = cur.fetchone()
    if not account:
        raise ValueError("Account not found")

    account_id = account[0]

    cur.execute("""
        INSERT INTO domains (account_id, uid, domain_name) VALUES (%s, %s, %s);
    """, (account_id, domain_uid, domain_name))
    conn.commit()
    cur.close()
    conn.close()

def create_scan(account_uid, domain_uid, scan_uid):
    """
    Insert a new scan into the 'scans' table.
    """
    conn = get_connection()
    cur = conn.cursor()

    # Get the domain ID from the UID
    cur.execute("""
        SELECT d.id FROM domains d
        JOIN accounts a ON d.account_id = a.id
        WHERE a.uid = %s AND d.uid = %s;
    """, (account_uid, domain_uid))
    domain = cur.fetchone()
    if not domain:
        raise ValueError("Domain not found")

    domain_id = domain[0]

    cur.execute("""
        INSERT INTO scans (domain_id, uid) VALUES (%s, %s);
    """, (domain_id, scan_uid))
    conn.commit()
    cur.close()
    conn.close()

def get_scan(scan_uid):
    """
    Retrieve a scan by its UID.
    Returns a dictionary with column names as keys.
    """
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT * FROM scans WHERE uid = %s;
    """, (scan_uid,))
    scan = cur.fetchone()
    cur.close()
    conn.close()
    return scan

def get_endpoint_details(endpoint_uid):
    """
    Retrieve an endpoint by its UID.
    Returns a dictionary with column names as keys.
    """
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT * FROM endpoints WHERE uid = %s;
    """, (endpoint_uid,))
    endpoint = cur.fetchone()
    cur.close()
    conn.close()
    return endpoint

def update_scan_status(scan_uid, status):
    """
    Update the status of a scan by its UID.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE scans SET status = %s WHERE uid = %s;
    """, (status, scan_uid))
    conn.commit()
    cur.close()
    conn.close()

ALERT_SEVERITY_MAP = {
    "Vulnerable JS Library": "High",
    "CSP: Wildcard Directive": "Medium",
    "CSP: script-src unsafe-inline": "Medium",
    "CSP: style-src unsafe-inline": "Medium",
    "Source Code Disclosure - Ruby": "Medium",
    "Source Code Disclosure - SQL": "Medium",
    "Sub Resource Integrity Attribute Missing": "Medium",
    "CSP: Notices": "Low",
    "Cross-Domain JavaScript Source File Inclusion": "Low",
    "Permissions Policy Header Not Set": "Low",
    "Private IP Disclosure": "Low",
    "Server Leaks Information via \"X-Powered-By\"": "Low",
    "Server Leaks Version Information via \"Server\"": "Low",
    "Strict-Transport-Security Header Not Set": "Low",
    "Timestamp Disclosure - Unix": "Low",
    "X-Content-Type-Options Header Missing": "Low",
    "Content-Type Header Missing": "Informational",
    "Information Disclosure - Suspicious Comments": "Informational",
    "Modern Web Application": "Informational",
    "Non-Storable Content": "Informational",
    "Re-examine Cache-control Directives": "Informational",
    "Retrieved from Cache": "Informational",
    "Storable and Cacheable Content": "Informational" 
}

def insert_alert(endpoint_id, alert_data):
    conn = get_connection()
    cur = conn.cursor()

    name = alert_data.get("name", "")
    zap_severity = alert_data.get("severity", "Unknown")
    # If name is in the map, override the severity
    custom_severity = ALERT_SEVERITY_MAP.get(name, zap_severity)

    # Then do your INSERT with custom_severity
    cur.execute("""
        INSERT INTO alerts (
            endpoint_id, name, description, url, method, parameter, attack, evidence,
            other_info, instances, solution, references_list, severity,
            cwe_id, wasc_id, plugin_id
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
    """, (
        endpoint_id,
        name,
        alert_data.get("description"),
        alert_data.get("url"),
        alert_data.get("method", "GET"),
        alert_data.get("parameter"),
        alert_data.get("attack"),
        alert_data.get("evidence"),
        alert_data.get("other_info"),
        alert_data.get("instances", 1),
        alert_data.get("solution"),
        alert_data.get("references", []),
        custom_severity,
        alert_data.get("cwe_id"),
        alert_data.get("wasc_id"),
        alert_data.get("plugin_id"),
    ))
    alert_id = cur.fetchone()[0]

    cur.execute("""
        UPDATE endpoints
        SET alerts = array_append(alerts, %s)
        WHERE id = %s;
    """, (alert_id, endpoint_id))

    conn.commit()
    cur.close()
    conn.close()


def insert_subdomain(scan_id, subdomain):
    """
    Insert a subdomain into the 'subdomains' table.
    `scan_id` must be the integer primary key from `scans.id`.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO subdomains (scan_id, subdomain)
        VALUES (%s, %s);
    """, (scan_id, subdomain))
    conn.commit()
    cur.close()
    conn.close()

def insert_endpoint(scan_id, subdomain, ep_data):
    """
    Insert an endpoint into the 'endpoints' table and return its integer ID.
    `scan_id` must be the integer primary key from `scans.id`.
    """
    conn = get_connection()
    cur = conn.cursor()

    uid = str(uuid.uuid4())
    cur.execute("""
        INSERT INTO endpoints (
            scan_id, uid, subdomain, url, status_code, content_type, server, framework
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
    """, (
        scan_id,
        uid,
        subdomain,
        ep_data.get("url"),
        ep_data.get("status_code"),
        ep_data.get("content_type"),
        ep_data.get("server"),
        ep_data.get("framework"),
    ))
    endpoint_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return endpoint_id


def get_domain_name_by_uid(domain_uid):
    """
    Retrieve the domain_name from domains table by its UID (the UUID).
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT domain_name FROM domains WHERE uid = %s;
    """, (domain_uid,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row else None

def get_scan_id_by_uid(scan_uid):
    """
    Retrieve the integer primary key (id) for the given scan UID (the UUID).
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id FROM scans WHERE uid = %s;
    """, (scan_uid,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row else None


def get_scan_details(scan_uid, exclude_html=False):
    """
    Modified to:
      - only return distinct alert names (instead of repeating the same alert name).
      - keep 'scan_uid', 'status', 'subdomains' etc. at top-level, endpoints at bottom.
    """
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # 1) Fetch main scan row
    cur.execute("""
        SELECT s.uid AS scan_uid, s.status, s.created_at,
               d.uid AS domain_uid
        FROM scans s
        JOIN domains d ON s.domain_id = d.id
        WHERE s.uid = %s;
    """, (scan_uid,))
    scan_row = cur.fetchone()
    if not scan_row:
        cur.close()
        conn.close()
        return None

    # 2) Find integer scan PK
    cur.execute("SELECT id FROM scans WHERE uid = %s;", (scan_uid,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return None
    scan_pk = row["id"]

    # 3) Gather subdomains
    cur.execute("""
        SELECT subdomain
          FROM subdomains
         WHERE scan_id = %s
         ORDER BY subdomain;
    """, (scan_pk,))
    subdomains = [r["subdomain"] for r in cur.fetchall()]

    # 4) Gather endpoints + all alert objects
    cur.execute("""
        SELECT e.uid AS endpoint_uid,
               e.subdomain, e.url, e.status_code,
               e.content_type, e.server, e.framework,
               COALESCE(json_agg(
                 CASE WHEN a.id IS NOT NULL THEN
                   json_build_object(
                     'name', a.name,
                     'severity', a.severity,
                     'created_at', a.created_at
                   )
                 END
               ) FILTER (WHERE a.id IS NOT NULL), '[]') AS alerts_json
          FROM endpoints e
     LEFT JOIN alerts a ON e.id = a.endpoint_id
         WHERE e.scan_id = %s
         GROUP BY e.uid, e.subdomain, e.url, e.status_code,
                  e.content_type, e.server, e.framework
         ORDER BY e.uid;
    """, (scan_pk,))
    endpoint_rows = cur.fetchall()

    endpoints = []
    for er in endpoint_rows:
        # Check if we should skip "text/html" endpoints
        if exclude_html:
            ctype = (er["content_type"] or "").lower()
            if "text/html" in ctype:
                continue

        # Distinct alert names
        raw_alerts = er["alerts_json"] or []
        distinct_names = set()
        for a in raw_alerts:
            distinct_names.add(a["name"])
        # Sort them or not
        distinct_names_list = sorted(list(distinct_names))

        endpoints.append({
            "endpoint_uid": er["endpoint_uid"],
            "subdomain": er["subdomain"],
            "url": er["url"],
            "status_code": er["status_code"],
            "content_type": er["content_type"],
            "server": er["server"],
            "framework": er["framework"],
            # only the array of distinct names
            "alerts": distinct_names_list
        })

    cur.close()
    conn.close()

    return {
        # "Light info" at top:
        "scan_uid": scan_row["scan_uid"],
        "domain_uid": scan_row["domain_uid"],
        "status": scan_row["status"],
        "created_at": scan_row["created_at"],
        "subdomains": subdomains,
        "endpoints": endpoints
    }



def get_endpoint_with_alerts(endpoint_uid):
    """
    Returns:
      {
        "endpoint_uid": ...,
        "scan_uid": ...,
        "subdomain": ...,
        "url": ...,
        "status_code": ...,
        "content_type": ...,
        "server": ...,
        "framework": ...,
        "created_at": ...,
        "alerts": [
          {
            "alert_uid": ...,
            "name": ...,
            "severity": ...,
            ...
          }
        ]
      }
    """
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Fetch the endpoint row (with the scan UID)
    cur.execute("""
        SELECT e.uid AS endpoint_uid,
               s.uid AS scan_uid,
               e.subdomain, e.url, e.status_code,
               e.content_type, e.server, e.framework,
               e.created_at
        FROM endpoints e
        JOIN scans s ON e.scan_id = s.id
        WHERE e.uid = %s;
    """, (endpoint_uid,))
    endpoint_row = cur.fetchone()
    if not endpoint_row:
        cur.close()
        conn.close()
        return None

    # Gather the full alerts for that endpoint
    cur.execute("""
        SELECT a.id AS alert_uid,
               a.name, a.description, a.url, a.method,
               a.parameter, a.attack, a.evidence,
               a.other_info, a.instances,
               a.solution, a.references_list,
               a.severity, a.cwe_id, a.wasc_id,
               a.plugin_id, a.created_at
        FROM alerts a
        JOIN endpoints e ON a.endpoint_id = e.id
        WHERE e.uid = %s
        ORDER BY a.created_at;
    """, (endpoint_uid,))
    alerts = cur.fetchall()

    cur.close()
    conn.close()

    return {
        "endpoint_uid": endpoint_row["endpoint_uid"],
        "scan_uid": endpoint_row["scan_uid"],
        "subdomain": endpoint_row["subdomain"],
        "url": endpoint_row["url"],
        "status_code": endpoint_row["status_code"],
        "content_type": endpoint_row["content_type"],
        "server": endpoint_row["server"],
        "framework": endpoint_row["framework"],
        "created_at": endpoint_row["created_at"],
        "alerts": alerts
    }

