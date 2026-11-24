import argparse
import getpass
import os
import sys
import psycopg
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

def main():
    if not DATABASE_URL:
        print("Error: DATABASE_URL is not set in .env", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Securely set password for an existing active Admin in BugFlow.")
    parser.add_argument("--user-id", help="User ID of the admin (e.g. USR-001)")
    parser.add_argument("--email", help="Email of the admin")
    parser.add_argument("--password", help="Password to set (interactive prompt if omitted)")
    args = parser.parse_args()

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT user_id, display_name, email, role, active 
                FROM users 
                WHERE role = 'ADMIN' AND active = TRUE
                ORDER BY user_id
            """)
            admins = cur.fetchall()

            if not admins:
                print("No active administrator accounts found in users table.", file=sys.stderr)
                sys.exit(1)

            chosen_admin = None
            if args.user_id:
                chosen_admin = next((a for a in admins if a[0] == args.user_id), None)
            elif args.email:
                chosen_admin = next((a for a in admins if a[2].lower() == args.email.lower()), None)
            else:
                if len(admins) == 1:
                    chosen_admin = admins[0]
                    print(f"Selecting active administrator: {chosen_admin[1]} ({chosen_admin[2]}, ID: {chosen_admin[0]})")
                else:
                    print("Available active administrators:")
                    for idx, a in enumerate(admins, 1):
                        print(f" [{idx}] {a[0]}: {a[1]} ({a[2]})")
                    choice = input(f"Choose admin [1-{len(admins)}]: ").strip()
                    try:
                        chosen_admin = admins[int(choice) - 1]
                    except (ValueError, IndexError):
                        print("Invalid selection.", file=sys.stderr)
                        sys.exit(1)

            if not chosen_admin:
                print("Specified admin not found.", file=sys.stderr)
                sys.exit(1)

            password = args.password
            if not password:
                password = getpass.getpass(f"Enter new password for {chosen_admin[1]} ({chosen_admin[2]}): ")
                confirm = getpass.getpass("Confirm password: ")
                if password != confirm:
                    print("Passwords do not match.", file=sys.stderr)
                    sys.exit(1)

            if len(password) < 6:
                print("Password must be at least 6 characters long.", file=sys.stderr)
                sys.exit(1)

            password_hash = generate_password_hash(password)
            cur.execute("""
                UPDATE users 
                SET password_hash = %s 
                WHERE user_id = %s
            """, (password_hash, chosen_admin[0]))
            conn.commit()

            print(f"Password successfully set for administrator {chosen_admin[1]} ({chosen_admin[2]}).")

if __name__ == "__main__":
    main()
