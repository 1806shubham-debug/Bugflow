
import csv
import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
DATA_DIR = Path(__file__).parent / "data"

# Parent tables must be imported before dependent tables.
TABLES = {
    "users": "users.csv",
    "projects": "projects.csv",
    "workflow_states": "workflow_states.csv",
    "sprints": "sprints.csv",
    "issues": "issues.csv",
    "resolution_suggestions": "resolution_suggestions.csv",
}


def import_csv(cursor, table, filename):
    path = DATA_DIR / filename

    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        columns = reader.fieldnames

        if not columns:
            raise ValueError(f"No column headers found in {filename}")

        # Convert blank CSV cells to SQL NULL.
        rows = [
            {
                key: value if value != "" else None
                for key, value in row.items()
            }
            for row in reader
        ]

    column_sql = ", ".join(f'"{column}"' for column in columns)
    placeholders = ", ".join(["%s"] * len(columns))
    query = (
        f'INSERT INTO "{table}" ({column_sql}) '
        f"VALUES ({placeholders})"
    )

    values = [tuple(row[column] for column in columns) for row in rows]

    if values:
        cursor.executemany(query, values)

    print(f"{table}: imported {len(values)} records")


def main():
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL is missing from .env")

    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            # Refuse to mix this dataset with existing records.
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM users
            """
            )
            if cursor.fetchone()[0] != 0:
                raise RuntimeError(
                    "The users table is not empty. "
                    "Import stopped to avoid duplicate or mixed data."
                )

            for table, filename in TABLES.items():
                import_csv(cursor, table, filename)

    print("\nImport completed successfully.")


if __name__ == "__main__":
    main()
