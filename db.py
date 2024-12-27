# db.py
import os
import psycopg2

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

    # 'scans' table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            domain VARCHAR(255) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'queued',
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    # 'subdomains' table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            subdomain VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    conn.commit()
    cur.close()
    conn.close()

def create_scan(domain):
    """
    Insert a new row in the 'scans' table and return its ID.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (domain) VALUES (%s) RETURNING id;", (domain,))
    scan_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return scan_id

def get_scan(scan_id):
    """
    Return the scan record plus any subdomains discovered.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, domain, status, created_at
        FROM scans
        WHERE id = %s
    """, (scan_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return None

    scan_data = {
        "id": row[0],
        "domain": row[1],
        "status": row[2],
        "created_at": str(row[3])  # datetime -> string
    }

    # Collect all subdomains
    cur.execute("SELECT subdomain FROM subdomains WHERE scan_id = %s", (scan_id,))
    subdomains = [r[0] for r in cur.fetchall()]
    scan_data["subdomains"] = subdomains

    cur.close()
    conn.close()
    return scan_data

def update_scan_status(scan_id, status):
    """
    Update the 'status' field in the 'scans' table.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE scans SET status=%s WHERE id=%s;", (status, scan_id))
    conn.commit()
    cur.close()
    conn.close()

def insert_subdomain(scan_id, subdomain):
    """
    Insert a discovered subdomain into the 'subdomains' table.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO subdomains (scan_id, subdomain)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING
    """, (scan_id, subdomain))
    conn.commit()
    cur.close()
    conn.close()
