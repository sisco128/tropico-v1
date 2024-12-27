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
    Create the tables if they don't exist (scans, subdomains, endpoints).
    """
    conn = get_connection()
    cur = conn.cursor()

    # scans table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            domain VARCHAR(255) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'queued',
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    # subdomains table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            subdomain VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)

    # endpoints table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            subdomain VARCHAR(255) NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER,
            content_type VARCHAR(255),
            server VARCHAR(255),
            framework VARCHAR(255),
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
    Return the scan record plus subdomains (list) and endpoints (flattened list).
    {
      "id": ...,
      "domain": ...,
      "status": ...,
      "created_at": ...,
      "subdomains": [...],
      "endpoints": [
        {
          "subdomain": "...",
          "url": "...",
          "status_code": ...,
          "content_type": ...,
          "server": ...,
          "framework": ...
        },
        ...
      ]
    }
    """
    conn = get_connection()
    cur = conn.cursor()

    # fetch the scan row
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
        "created_at": str(row[3])
    }

    # fetch subdomains
    cur.execute("SELECT subdomain FROM subdomains WHERE scan_id = %s", (scan_id,))
    subdomain_rows = cur.fetchall()
    scan_data["subdomains"] = [r[0] for r in subdomain_rows]

    # fetch endpoints as a flattened list
    cur.execute("""
        SELECT subdomain, url, status_code, content_type, server, framework
        FROM endpoints
        WHERE scan_id = %s
    """, (scan_id,))
    endpoint_rows = cur.fetchall()

    endpoints_list = []
    for (subd, url, st_code, ctype, srv, fw) in endpoint_rows:
        endpoints_list.append({
            "subdomain": subd,
            "url": url,
            "status_code": st_code,
            "content_type": ctype,
            "server": srv,
            "framework": fw
        })

    scan_data["endpoints"] = endpoints_list

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
    Insert a discovered subdomain into 'subdomains' table.
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

def insert_endpoint(scan_id, subdomain, endpoint_data):
    """
    Insert a discovered endpoint (URL, status_code, content_type, etc.) into 'endpoints' table.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO endpoints (scan_id, subdomain, url, status_code, content_type, server, framework)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
    """, (
        scan_id,
        subdomain,
        endpoint_data["url"],
        endpoint_data["status_code"],
        endpoint_data["content_type"],
        endpoint_data["server"],
        endpoint_data["framework"],
    ))
    conn.commit()
    cur.close()
    conn.close()
