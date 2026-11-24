import os
import psycopg
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

def run_migration():
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL not set in .env")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            # Safe additive migration: add password_hash column if not exists
            cur.execute("""
                ALTER TABLE users 
                ADD COLUMN IF NOT EXISTS password_hash TEXT;
            """)
            conn.commit()
            print("Migration successful: password_hash column ensured on users table.")

if __name__ == "__main__":
    run_migration()
