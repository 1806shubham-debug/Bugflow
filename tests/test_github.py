import base64
import datetime
import hashlib
import hmac
import json
import os
import sys

# Ensure app can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, get_db
from werkzeug.security import generate_password_hash

TEST_SECRET = "test-bugflow-webhook-secret-key-12345"

def make_signature(secret, body_bytes):
    """Computes the GitHub X-Hub-Signature-256 header."""
    digest = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_github():
    print("Running BugFlow GitHub Webhook Integration test suite...")
    app.config["TESTING"] = True
    client = app.test_client()

    # Set test webhook secret
    os.environ["GITHUB_WEBHOOK_SECRET"] = TEST_SECRET

    # Authenticate admin user for issue detail verification
    with app.app_context():
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE user_id = 'USR-001'")
            orig_admin_hash = cur.fetchone()["password_hash"]
            cur.execute(
                "UPDATE users SET password_hash = %s WHERE user_id = 'USR-001'", 
                (generate_password_hash("AdminPass123!"),)
            )
            conn.commit()

    test_sha_1 = "test-sha-github-commit-00000000000001"
    test_sha_dup = "test-sha-github-commit-00000000000002"
    test_sha_no_id = "test-sha-github-commit-00000000000003"
    test_sha_bad_id = "test-sha-github-commit-00000000000004"

    try:
        # -------------------------------------------------------------
        # 1. Missing Webhook Signature is Rejected (401)
        # -------------------------------------------------------------
        payload_data = {"ref": "refs/heads/main", "commits": []}
        payload_bytes = json.dumps(payload_data).encode("utf-8")
        res = client.post("/webhooks/github", data=payload_bytes, content_type="application/json")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}"
        assert "Missing" in res.get_json()["message"]
        print("  [PASS] 1. Missing webhook signature is rejected with 401.")

        # -------------------------------------------------------------
        # 2. Invalid Webhook Signature is Rejected (403)
        # -------------------------------------------------------------
        bad_headers = {
            "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            "X-GitHub-Event": "push",
            "Content-Type": "application/json"
        }
        res = client.post("/webhooks/github", data=payload_bytes, headers=bad_headers)
        assert res.status_code == 403, f"Expected 403, got {res.status_code}"
        assert res.get_json()["error"] == "Forbidden"
        print("  [PASS] 2. Invalid webhook signature is rejected with 403.")

        # -------------------------------------------------------------
        # 3. Valid Signed Push Event is Accepted (200)
        # -------------------------------------------------------------
        sig = make_signature(TEST_SECRET, payload_bytes)
        headers = {
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "push",
            "Content-Type": "application/json"
        }
        res = client.post("/webhooks/github", data=payload_bytes, headers=headers)
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        assert res.get_json()["success"] is True
        print("  [PASS] 3. Valid signed push event is accepted with 200.")

        # -------------------------------------------------------------
        # 4. Commit Linked to an Existing Issue is Saved
        # -------------------------------------------------------------
        # We link to BUG-00001 (historical existing issue)
        commit_payload = {
            "ref": "refs/heads/main",
            "repository": {
                "name": "bugflow-improved",
                "full_name": "octocat/bugflow-improved",
                "html_url": "https://github.com/octocat/bugflow-improved"
            },
            "commits": [
                {
                    "id": test_sha_1,
                    "message": "Resolve BUG-00001: Fix query trailing whitespace and update parser",
                    "timestamp": "2026-11-19T14:30:00Z",
                    "url": f"https://github.com/octocat/bugflow-improved/commit/{test_sha_1}",
                    "author": {
                        "name": "Alex Morgan",
                        "email": "alex.morgan@example.org"
                    }
                }
            ]
        }
        commit_bytes = json.dumps(commit_payload).encode("utf-8")
        headers["X-Hub-Signature-256"] = make_signature(TEST_SECRET, commit_bytes)

        res = client.post("/webhooks/github", data=commit_bytes, headers=headers)
        assert res.status_code == 200
        assert res.get_json()["linked_commits"] == 1

        # Verify record in database
        with app.app_context():
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM commits WHERE commit_sha = %s", (test_sha_1,))
                saved = cur.fetchone()
                assert saved is not None
                assert saved["issue_id"] == "BUG-00001"
                assert saved["commit_author"] == "Alex Morgan"
                assert saved["repository_name"] == "octocat/bugflow-improved"
                assert "BUG-00001" in saved["commit_message"]
        print("  [PASS] 4. Commit linked to an existing issue is saved in commits table.")

        # -------------------------------------------------------------
        # 5. Commit Without a BugFlow Issue ID is Skipped
        # -------------------------------------------------------------
        no_id_payload = {
            "ref": "refs/heads/main",
            "repository": {"full_name": "octocat/bugflow-improved"},
            "commits": [
                {
                    "id": test_sha_no_id,
                    "message": "Refactor logging helpers without issue reference",
                    "timestamp": "2026-11-19T14:32:00Z",
                    "author": {"name": "Jordan Lee"}
                }
            ]
        }
        no_id_bytes = json.dumps(no_id_payload).encode("utf-8")
        headers["X-Hub-Signature-256"] = make_signature(TEST_SECRET, no_id_bytes)
        res = client.post("/webhooks/github", data=no_id_bytes, headers=headers)
        assert res.status_code == 200
        assert res.get_json()["linked_commits"] == 0

        with app.app_context():
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT commit_id FROM commits WHERE commit_sha = %s", (test_sha_no_id,))
                assert cur.fetchone() is None
        print("  [PASS] 5. Commit without a BugFlow issue ID is safely skipped.")

        # -------------------------------------------------------------
        # 6. Non-Existent Issue ID is Skipped
        # -------------------------------------------------------------
        bad_id_payload = {
            "ref": "refs/heads/main",
            "repository": {"full_name": "octocat/bugflow-improved"},
            "commits": [
                {
                    "id": test_sha_bad_id,
                    "message": "Fix BUG-99999: Reference to a non-existent defect",
                    "timestamp": "2026-11-19T14:34:00Z",
                    "author": {"name": "Riley Chen"}
                }
            ]
        }
        bad_id_bytes = json.dumps(bad_id_payload).encode("utf-8")
        headers["X-Hub-Signature-256"] = make_signature(TEST_SECRET, bad_id_bytes)
        res = client.post("/webhooks/github", data=bad_id_bytes, headers=headers)
        assert res.status_code == 200
        assert res.get_json()["linked_commits"] == 0

        with app.app_context():
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT commit_id FROM commits WHERE commit_sha = %s", (test_sha_bad_id,))
                assert cur.fetchone() is None
        print("  [PASS] 6. Non-existent issue ID is safely skipped.")

        # -------------------------------------------------------------
        # 7. Duplicate Commit is Not Inserted Twice
        # -------------------------------------------------------------
        dup_payload = {
            "ref": "refs/heads/main",
            "repository": {"full_name": "octocat/bugflow-improved"},
            "commits": [
                {
                    "id": test_sha_dup,
                    "message": "BUG-00001: First push delivery",
                    "timestamp": "2026-11-19T14:35:00Z",
                    "author": {"name": "Alex Morgan"}
                }
            ]
        }
        dup_bytes = json.dumps(dup_payload).encode("utf-8")
        headers["X-Hub-Signature-256"] = make_signature(TEST_SECRET, dup_bytes)

        # First delivery -> inserted (linked_commits == 1)
        res1 = client.post("/webhooks/github", data=dup_bytes, headers=headers)
        assert res1.status_code == 200
        assert res1.get_json()["linked_commits"] == 1

        # Second delivery (replay/retry) -> skipped via ON CONFLICT DO NOTHING (linked_commits == 0)
        res2 = client.post("/webhooks/github", data=dup_bytes, headers=headers)
        assert res2.status_code == 200
        assert res2.get_json()["linked_commits"] == 0

        with app.app_context():
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS cnt FROM commits WHERE commit_sha = %s", (test_sha_dup,))
                assert cur.fetchone()["cnt"] == 1
        print("  [PASS] 7. Duplicate commit is not inserted twice (ON CONFLICT DO NOTHING).")

        # -------------------------------------------------------------
        # 8. Unsupported GitHub Event is Handled Safely
        # -------------------------------------------------------------
        ping_headers = {
            "X-Hub-Signature-256": make_signature(TEST_SECRET, payload_bytes),
            "X-GitHub-Event": "ping",
            "Content-Type": "application/json"
        }
        res = client.post("/webhooks/github", data=payload_bytes, headers=ping_headers)
        assert res.status_code == 200
        assert res.get_json()["status"] == "ignored"
        print("  [PASS] 8. Unsupported GitHub event (ping) is handled safely.")

        # -------------------------------------------------------------
        # 9. Issue Detail Page Displays Linked Commits
        # -------------------------------------------------------------
        # Log in Admin
        login_page = client.get("/login")
        with client.session_transaction() as sess:
            csrf = sess["csrf_token"]
        login_res = client.post("/login", data={
            "csrf_token": csrf,
            "email": "alex.morgan@example.org",
            "password": "AdminPass123!"
        }, follow_redirects=True)
        assert login_res.status_code == 200

        # View BUG-00001
        res = client.get("/issues/BUG-00001")
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert "GitHub Commits" in html
        assert test_sha_1[:7] in html
        assert "Alex Morgan" in html
        assert "octocat/bugflow-improved" in html
        assert "Fix query trailing whitespace" in html
        print("  [PASS] 9. Issue detail page displays linked GitHub commits and shortened SHA.")

        # -------------------------------------------------------------
        # 10. Missing Webhook Secret Fails Safely (500)
        # -------------------------------------------------------------
        os.environ.pop("GITHUB_WEBHOOK_SECRET", None)
        try:
            res = client.post("/webhooks/github", data=payload_bytes, headers=headers)
            assert res.status_code == 500
            assert res.get_json()["error"] == "Configuration Error"
            print("  [PASS] 10. Missing webhook secret fails safely with 500.")
        finally:
            os.environ["GITHUB_WEBHOOK_SECRET"] = TEST_SECRET

        print("\nALL 10 GITHUB INTEGRATION TESTS PASSED CLEANLY! (100% success)")

    finally:
        # Cleanup test commit records
        with app.app_context():
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM commits WHERE commit_sha IN (%s, %s, %s, %s)",
                    (test_sha_1, test_sha_dup, test_sha_no_id, test_sha_bad_id)
                )
                cur.execute(
                    "UPDATE users SET password_hash = %s WHERE user_id = 'USR-001'", 
                    (orig_admin_hash,)
                )
                conn.commit()

if __name__ == "__main__":
    test_github()

