
import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL or "PASTE_YOUR_NEON" in DATABASE_URL:
    raise ValueError("Please configure DATABASE_URL in your .env file.")

try:
    with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version(), current_database()")
            version, database = cur.fetchone()

    print("Connected to Neon successfully!")
    print("Database:", database)
    print("PostgreSQL version:", version.split(",")[0])

except Exception as error:
    print("Database connection failed.")
    print("Error type:", type(error).__name__)
    print("Check your Neon connection settings.")
