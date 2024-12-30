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

    # accounts table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            uid UUID NOT NULL DEFAULT gen_random_uuid(),
            account_name VARCHAR(255) NOT NULL,
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
            alerts UUID[] DEFAULT ARRAY[]::UUID[],  -- Array of related alert IDs
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

def create_account(account_uid, account_name):
    """
    Insert a new account into the 'accounts' table.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO accounts (uid, account_name)
        VALUES (%s, %s);
    """, (account_uid, account_name))

    conn.commit()
    cur.close()
    conn.close()

def create_domain(account_uid, domain_uid, domain_name):
    """
    Insert a new domain into the 'scans' table.
    """
    conn = get_connection()
    cur = conn.cursor()

    # Find the account ID using account_uid
    cur.execute("""
        SELECT id FROM accounts WHERE uid = %s;
    """, (account_uid,))
    account_id = cur.fetchone()
    if not account_id:
        raise ValueError("Account not found")

    # Insert the domain
    cur.execute("""
        INSERT INTO scans (account_id, domain, status)
        VALUES (%s, %s, 'queued');
    """, (account_id[0], domain_name))

    conn.commit()
    cur.close()
    conn.close()

def create_scan(account_uid, domain_uid, scan_uid):
    """
    Insert a new scan into the 'scans' table.
    """
    conn = get_connection()
    cur = conn.cursor()

    # Find the account ID and domain
    cur.execute("""
        SELECT a.id, s.id FROM accounts a
        JOIN scans s ON a.id = s.account_id
        WHERE a.uid = %s AND s.domain = %s;
    """, (account_uid, domain_uid))
    result = cur.fetchone()
    if not result:
        raise ValueError("Account or domain not found")

    account_id, domain_id = result

    # Insert the scan
    cur.execute("""
        INSERT INTO scans (account_id, domain, status)
        VALUES (%s, %s, 'queued');
    """, (account_id, domain_uid))

    conn.commit()
    cur.close()
    conn.close()

def get_scan(scan_id):
    """
    Retrieve scan data by scan_id.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, account_id, domain, status, created_at
        FROM scans WHERE id = %s;
    """, (scan_id,))
    scan_data = cur.fetchone()

    cur.close()
    conn.close()

    if scan_data:
        return {
            "id": scan_data[0],
            "account_id": scan_data[1],
            "domain": scan_data[2],
            "status": scan_data[3],
            "created_at": scan_data[4]
        }
    return None

def get_endpoint_details(endpoint_id):
    """
    Retrieve endpoint details by endpoint_id.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM endpoints WHERE id = %s;
    """, (endpoint_id,))
    endpoint_data = cur.fetchone()

    cur.close()
    conn.close()

    return endpoint_data
