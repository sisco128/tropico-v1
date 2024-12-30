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
    """
    conn = get_connection()
    cur = conn.cursor()
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
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM endpoints WHERE id = %s;
    """, (endpoint_uid,))
    endpoint = cur.fetchone()
    cur.close()
    conn.close()
    return endpoint
