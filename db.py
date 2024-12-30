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

def insert_alert(endpoint_id, alert_data):
    """
    Insert a new alert into the 'alerts' table.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO alerts (
            endpoint_id, name, description, url, method, parameter, attack, evidence,
            other_info, instances, solution, references, severity, cwe_id, wasc_id, plugin_id
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        ) RETURNING id;
    """, (
        endpoint_id,
        alert_data["name"],
        alert_data["description"],
        alert_data["url"],
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
    conn.commit()
    cur.close()
    conn.close()

    return alert_id
