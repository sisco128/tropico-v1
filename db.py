import os
import psycopg2
from psycopg2.extras import RealDictCursor
import uuid

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

def insert_alert(endpoint_id, alert_data):
    """
    Insert a new alert into the 'alerts' table.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO alerts (
            endpoint_id, name, description, url, method, parameter, attack, evidence,
            other_info, instances, solution, references_list, severity, cwe_id, wasc_id, plugin_id
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        ) RETURNING id;
    """, (
        endpoint_id,
        alert_data.get("name"),
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
        alert_data.get("severity"),
        alert_data.get("cwe_id"),
        alert_data.get("wasc_id"),
        alert_data.get("plugin_id"),
    ))
    alert_id = cur.fetchone()[0]

    # Optionally, update the alerts array in the endpoints table
    cur.execute("""
        UPDATE endpoints SET alerts = array_append(alerts, %s) WHERE id = %s;
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
