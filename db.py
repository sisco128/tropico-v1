import os
import psycopg2
from psycopg2.extras import RealDictCursor

def get_connection():
    """
    Connect to Postgres using DATABASE_URL or fallback DSN with 'localhost'.
    """
    db_url = os.getenv("DATABASE_URL") or "postgres://siscolo:@localhost:5432/my_local_db"
    return psycopg2.connect(db_url, cursor_factory=RealDictCursor)

def init_db():
    """
    Create the tables if they don't exist.
    """
    conn = get_connection()
    cur = conn.cursor()

    # accounts table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            uid UUID NOT NULL DEFAULT gen_random_uuid(),
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    # scans table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            domain VARCHAR(255) NOT NULL,
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
            references TEXT[],
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

def create_account():
    """
    Create a new account and return its details.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO accounts (uid, created_at)
        VALUES (gen_random_uuid(), NOW())
        RETURNING *;
    """)
    account = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return account

def create_scan(account_id, domain):
    """
    Create a new scan and return its details.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO scans (account_id, domain, status, created_at)
        VALUES (%s, %s, 'queued', NOW())
        RETURNING *;
    """, (account_id, domain))
    scan = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return scan

def get_scan(scan_id):
    """
    Get scan details by ID.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM scans WHERE id = %s;
    """, (scan_id,))
    scan = cur.fetchone()
    cur.close()
    conn.close()
    return scan

def get_endpoint_details(scan_id):
    """
    Get all endpoint details for a specific scan.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM endpoints WHERE scan_id = %s;
    """, (scan_id,))
    endpoints = cur.fetchall()
    cur.close()
    conn.close()
    return endpoints

def create_domain(scan_id, subdomain, url):
    """
    Create a new endpoint under a domain.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO endpoints (scan_id, subdomain, url, created_at)
        VALUES (%s, %s, %s, NOW())
        RETURNING *;
    """, (scan_id, subdomain, url))
    endpoint = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return endpoint
