import os
import psycopg2


def get_connection():
    db_url = os.getenv("DATABASE_URL", "postgres://siscolo:@localhost:5432/my_local_db")
    return psycopg2.connect(db_url)


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            uid UUID NOT NULL DEFAULT gen_random_uuid(),
            account_name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            domain VARCHAR(255) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'queued',
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            subdomain VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            url TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)
    conn.commit()
    cur.close()
    conn.close()


def create_account(account_uid, account_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO accounts (uid, account_name) VALUES (%s, %s);", (account_uid, account_name))
    conn.commit()
    cur.close()
    conn.close()


def create_domain(account_uid, domain_uid, domain_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (account_id, domain, uid) VALUES (%s, %s, %s);", (account_uid, domain_name, domain_uid))
    conn.commit()
    cur.close()
    conn.close()


def create_scan(account_uid, domain_uid, scan_uid):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (account_id, uid) VALUES (%s, %s);", (account_uid, scan_uid))
    conn.commit()
    cur.close()
    conn.close()
