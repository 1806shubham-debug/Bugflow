import os
import sys
import json
import urllib.parse
import subprocess
import psycopg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

EXISTING_TABLES = [
    "users",
    "projects",
    "workflow_states",
    "sprints",
    "issues",
    "resolution_suggestions",
    "comments",
    "attachments",
    "activity_history"
]

def get_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set.")
    try:
        return psycopg.connect(DATABASE_URL)
    except psycopg.OperationalError as e:
        if "getaddrinfo failed" in str(e):
            u = urllib.parse.urlparse(DATABASE_URL)
            res = subprocess.check_output(
                ["powershell", "-Command", f"(Resolve-DnsName {u.hostname} -Server 8.8.8.8 -Type A).IP4Address"],
                text=True
            ).strip().split()
            if res:
                return psycopg.connect(DATABASE_URL, hostaddr=res[0])
        raise

def run():
    results = {}

    with get_connection() as conn:
        with conn.cursor() as cur:
            # 1. Capture baseline counts
            baseline_counts = {}
            for tbl in EXISTING_TABLES:
                cur.execute(f"SELECT COUNT(*) FROM {tbl};")
                baseline_counts[tbl] = cur.fetchone()[0]

            results["baseline_counts"] = baseline_counts

            # 2. Read migration SQL
            migration_path = os.path.join(os.path.dirname(__file__), "milestone3.sql")
            with open(migration_path, "r", encoding="utf-8") as f:
                sql_content = f.read()

            # 3. Execute inside transaction
            with conn.transaction():
                cur.execute(sql_content)

            # 4. Verification: check table existence
            cur.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = 'commits';
            """)
            results["table_exists"] = bool(cur.fetchone())

            # 5. Columns verification
            cur.execute("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'commits'
                ORDER BY ordinal_position;
            """)
            results["columns"] = [
                {
                    "name": row[0],
                    "type": row[1],
                    "nullable": row[2],
                    "default": row[3]
                }
                for row in cur.fetchall()
            ]

            # 6. Primary Key verification
            cur.execute("""
                SELECT kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                WHERE tc.table_name = 'commits' AND tc.constraint_type = 'PRIMARY KEY';
            """)
            results["primary_key"] = [row[0] for row in cur.fetchall()]

            # 7. Unique Constraints
            cur.execute("""
                SELECT tc.constraint_name, kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                WHERE tc.table_name = 'commits' AND tc.constraint_type = 'UNIQUE';
            """)
            results["unique_constraints"] = [
                {"constraint": row[0], "column": row[1]} for row in cur.fetchall()
            ]

            # 8. Foreign Keys
            cur.execute("""
                SELECT
                    kcu.column_name,
                    ccu.table_name AS foreign_table_name,
                    ccu.column_name AS foreign_column_name,
                    rc.delete_rule
                FROM information_schema.table_constraints AS tc
                JOIN information_schema.key_column_usage AS kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                JOIN information_schema.referential_constraints AS rc
                  ON tc.constraint_name = rc.constraint_name
                JOIN information_schema.constraint_column_usage AS ccu
                  ON ccu.constraint_name = tc.constraint_name
                WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_name = 'commits';
            """)
            results["foreign_keys"] = [
                {
                    "column": row[0],
                    "foreign_table": row[1],
                    "foreign_column": row[2],
                    "on_delete": row[3]
                }
                for row in cur.fetchall()
            ]

            # 9. Indexes verification
            cur.execute("""
                SELECT indexname, indexdef
                FROM pg_indexes
                WHERE tablename = 'commits';
            """)
            results["indexes"] = [
                {"name": row[0], "definition": row[1]} for row in cur.fetchall()
            ]

            # 10. Post-migration row counts of existing tables
            post_counts = {}
            for tbl in EXISTING_TABLES:
                cur.execute(f"SELECT COUNT(*) FROM {tbl};")
                post_counts[tbl] = cur.fetchone()[0]

            results["post_counts"] = post_counts
            cur.execute("SELECT COUNT(*) FROM commits;")
            results["commits_count"] = cur.fetchone()[0]

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run()
