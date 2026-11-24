import base64
import os
import sys
from dotenv import load_dotenv

# Ensure app can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, get_db
from werkzeug.security import generate_password_hash

def test_api():
    print("Running BugFlow REST API Security & Functional test suite...")
    app.config["TESTING"] = True
    client = app.test_client()

    # Authenticate admin user
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

    try:
        # -------------------------------------------------------------
        # 1. Unauthorized Requests (401)
        # -------------------------------------------------------------
        # Unauthenticated GET
        res = client.get("/api/issues")
        assert res.status_code == 401, f"Expected 401, got {res.status_code}"
        data = res.get_json()
        assert data["success"] is False
        assert data["error"] == "Unauthorized"
        print("  [PASS] Unauthenticated GET /api/issues rejected with 401.")

        # Unauthenticated POST
        res = client.post("/api/issues", json={"title": "Test"})
        assert res.status_code == 401
        print("  [PASS] Unauthenticated POST /api/issues rejected with 401.")

        # Unauthenticated PUT
        res = client.put("/api/issues/BUG-00001", json={"title": "Test"})
        assert res.status_code == 401
        print("  [PASS] Unauthenticated PUT /api/issues rejected with 401.")

        # Unauthenticated DELETE
        res = client.delete("/api/issues/BUG-00001")
        assert res.status_code == 401
        print("  [PASS] Unauthenticated DELETE /api/issues rejected with 401.")

        # Unauthenticated PATCH assign
        res = client.patch("/api/issues/BUG-00001/assign", json={"assigned_to": "USR-002"})
        assert res.status_code == 401
        print("  [PASS] Unauthenticated PATCH assign rejected with 401.")

        # Unauthenticated PATCH status
        res = client.patch("/api/issues/BUG-00001/status", json={"status": "In Progress"})
        assert res.status_code == 401
        print("  [PASS] Unauthenticated PATCH status rejected with 401.")

        # Unauthenticated project issues
        res = client.get("/api/projects/PRJ-001/issues")
        assert res.status_code == 401
        print("  [PASS] Unauthenticated GET /api/projects/<id>/issues rejected with 401.")

        # -------------------------------------------------------------
        # Log in Admin client (Establishes browser session cookie)
        # -------------------------------------------------------------
        login_page = client.get("/login")
        with client.session_transaction() as sess:
            csrf_token = sess["csrf_token"]
        login_res = client.post("/login", data={
            "csrf_token": csrf_token,
            "email": "alex.morgan@example.org",
            "password": "AdminPass123!"
        }, follow_redirects=True)
        assert login_res.status_code == 200

        with client.session_transaction() as sess:
            auth_csrf_token = sess["csrf_token"]

        auth_headers = {"X-CSRF-Token": auth_csrf_token}

        # -------------------------------------------------------------
        # 2. Session-Authenticated CSRF Protection
        # -------------------------------------------------------------
        # A. State-changing request with session cookie but missing CSRF token -> 403 Forbidden
        csrf_missing_res = client.post("/api/issues", json={
            "project_id": "PRJ-001",
            "title": "CSRF Attack Attempt",
            "description": "Cross-site request forgery attempt"
        })
        assert csrf_missing_res.status_code == 403
        assert csrf_missing_res.get_json()["error"] == "CSRF Error"
        print("  [PASS] Session-authenticated POST without CSRF token rejected with 403.")

        # B. State-changing request with session cookie but forged/invalid CSRF token -> 403 Forbidden
        csrf_bad_res = client.post("/api/issues", json={
            "project_id": "PRJ-001",
            "title": "CSRF Attack Attempt",
            "description": "Forged token attempt"
        }, headers={"X-CSRF-Token": "forged_malicious_token_12345"})
        assert csrf_bad_res.status_code == 403
        assert csrf_bad_res.get_json()["error"] == "CSRF Error"
        print("  [PASS] Session-authenticated POST with forged CSRF token rejected with 403.")

        # C. HTTP Basic Auth client (no session cookie) succeeds without requiring CSRF token
        basic_client = app.test_client()
        basic_creds = base64.b64encode(b"alex.morgan@example.org:AdminPass123!").decode("ascii")
        basic_headers = {"Authorization": f"Basic {basic_creds}"}
        basic_get = basic_client.get("/api/issues", headers=basic_headers)
        assert basic_get.status_code == 200
        print("  [PASS] HTTP Basic Auth API client authenticated without ambient session.")

        # -------------------------------------------------------------
        # 3. Missing Resource Validation (404)
        # -------------------------------------------------------------
        res = client.get("/api/issues/BUG-99999")
        assert res.status_code == 404
        assert res.get_json()["success"] is False
        print("  [PASS] Missing issue GET returns 404.")

        res = client.put("/api/issues/BUG-99999", json={"title": "New Title"}, headers=auth_headers)
        assert res.status_code == 404
        print("  [PASS] Missing issue PUT returns 404.")

        res = client.delete("/api/issues/BUG-99999", headers=auth_headers)
        assert res.status_code == 404
        print("  [PASS] Missing issue DELETE returns 404.")

        res = client.patch("/api/issues/BUG-99999/assign", json={"assigned_to": "USR-002"}, headers=auth_headers)
        assert res.status_code == 404
        print("  [PASS] Missing issue PATCH assign returns 404.")

        res = client.patch("/api/issues/BUG-99999/status", json={"status": "In Progress"}, headers=auth_headers)
        assert res.status_code == 404
        print("  [PASS] Missing issue PATCH status returns 404.")

        res = client.get("/api/projects/PRJ-999/issues")
        assert res.status_code == 404
        print("  [PASS] Missing project GET issues returns 404.")

        # -------------------------------------------------------------
        # 4. Strict Input Validation & Unexpected Field Rejection (400)
        # -------------------------------------------------------------
        # Non-JSON payload
        res = client.post("/api/issues", data="raw string", content_type="text/plain", headers=auth_headers)
        assert res.status_code == 400
        print("  [PASS] Non-JSON payload rejected with 400.")

        # Missing required fields
        res = client.post("/api/issues", json={"title": "Missing fields"}, headers=auth_headers)
        assert res.status_code == 400
        assert "required" in res.get_json()["message"]
        print("  [PASS] Missing required fields rejected with 400.")

        # Unexpected fields in POST
        res = client.post("/api/issues", json={
            "project_id": "PRJ-001",
            "title": "Invalid Field Injection",
            "description": "Payload with unexpected columns",
            "injected_admin_flag": True,
            "secret_backdoor": "enabled"
        }, headers=auth_headers)
        assert res.status_code == 400
        assert "Unexpected fields" in res.get_json()["message"]
        print("  [PASS] Unexpected fields in POST payload rejected with 400.")

        # Unexpected fields in PUT
        res = client.put("/api/issues/BUG-00001", json={
            "title": "Valid Title",
            "illegal_column": 123
        }, headers=auth_headers)
        assert res.status_code == 400
        assert "Unexpected fields" in res.get_json()["message"]
        print("  [PASS] Unexpected fields in PUT payload rejected with 400.")

        # Unexpected fields in PATCH assign
        res = client.patch("/api/issues/BUG-00001/assign", json={
            "assigned_to": "USR-002",
            "unauthorized_role": "ADMIN"
        }, headers=auth_headers)
        assert res.status_code == 400
        assert "Unexpected fields" in res.get_json()["message"]
        print("  [PASS] Unexpected fields in PATCH assign rejected with 400.")

        # Invalid issue_type
        res = client.post("/api/issues", json={
            "project_id": "PRJ-001",
            "title": "Invalid Type",
            "description": "Desc",
            "issue_type": "InvalidTypeXYZ"
        }, headers=auth_headers)
        assert res.status_code == 400
        print("  [PASS] Invalid issue_type rejected with 400.")

        # Invalid severity
        res = client.post("/api/issues", json={
            "project_id": "PRJ-001",
            "title": "Invalid Sev",
            "description": "Desc",
            "severity": "SuperCritical"
        }, headers=auth_headers)
        assert res.status_code == 400
        print("  [PASS] Invalid severity rejected with 400.")

        # Invalid priority
        res = client.post("/api/issues", json={
            "project_id": "PRJ-001",
            "title": "Invalid Pri",
            "description": "Desc",
            "priority": "P99"
        }, headers=auth_headers)
        assert res.status_code == 400
        print("  [PASS] Invalid priority rejected with 400.")

        # Non-existent project
        res = client.post("/api/issues", json={
            "project_id": "PRJ-999",
            "title": "Invalid Prj",
            "description": "Desc"
        }, headers=auth_headers)
        assert res.status_code == 400
        assert "does not exist" in res.get_json()["message"]
        print("  [PASS] Non-existent project rejected with 400.")

        # Sprint does not belong to project
        res = client.post("/api/issues", json={
            "project_id": "PRJ-001",
            "title": "Cross-Project Sprint",
            "description": "Attempting sprint from PRJ-002",
            "sprint_id": "SP-02-01"
        }, headers=auth_headers)
        assert res.status_code == 400
        assert "belongs to project 'PRJ-002', not 'PRJ-001'" in res.get_json()["message"]
        print("  [PASS] Cross-project sprint assignment rejected with 400.")

        # -------------------------------------------------------------
        # 5. Invalid User Assignment (400)
        # -------------------------------------------------------------
        res = client.patch("/api/issues/BUG-00001/assign", json={"assigned_to": "USR-999"}, headers=auth_headers)
        assert res.status_code == 400
        assert "invalid or inactive" in res.get_json()["message"]
        print("  [PASS] Invalid user assignment rejected with 400.")

        # -------------------------------------------------------------
        # 6. Invalid Workflow Transitions (400)
        # -------------------------------------------------------------
        with app.app_context():
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT issue_id FROM issues WHERE status = 'Open' LIMIT 1")
                open_issue_id = cur.fetchone()["issue_id"]
                cur.execute("SELECT issue_id FROM issues WHERE status = 'Closed' LIMIT 1")
                closed_issue_id = cur.fetchone()["issue_id"]

        # Attempt to skip lifecycle stages: Open -> Resolved (skipping In Progress and Testing)
        res = client.patch(f"/api/issues/{open_issue_id}/status", json={"status": "Resolved"}, headers=auth_headers)
        assert res.status_code == 400
        assert res.get_json()["error"] == "Invalid workflow transition"
        assert "Cannot move from 'Open' to 'Resolved'" in res.get_json()["message"]

        # Attempt to transition out of terminal state: Closed -> Open
        res_terminal = client.patch(f"/api/issues/{closed_issue_id}/status", json={"status": "Open"}, headers=auth_headers)
        assert res_terminal.status_code == 400
        assert res_terminal.get_json()["error"] == "Invalid workflow transition"
        print("  [PASS] Skipping lifecycle stages and terminal state transitions rejected with 400.")

        # -------------------------------------------------------------
        # 7. Role-Based & Cross-Project Scope Authorization (403)
        # -------------------------------------------------------------
        # A. Developer (USR-005: Riley Chen) blocked from creating issue
        dev_headers = {"X-Test-User-ID": "USR-005"}
        res = client.post("/api/issues", json={
            "project_id": "PRJ-001",
            "title": "Dev Issue",
            "description": "Dev Desc"
        }, headers=dev_headers)
        assert res.status_code == 403
        assert res.get_json()["error"] == "Forbidden"
        print("  [PASS] Developer role blocked from issue creation with 403.")

        # Developer blocked from deleting issue
        res = client.delete("/api/issues/BUG-00001", headers=dev_headers)
        assert res.status_code == 403
        print("  [PASS] Developer role blocked from issue deletion with 403.")

        # Developer blocked from assigning issue
        res = client.patch("/api/issues/BUG-00001/assign", json={"assigned_to": "USR-002"}, headers=dev_headers)
        assert res.status_code == 403
        print("  [PASS] Developer role blocked from issue assignment with 403.")

        # B. Project Manager Cross-Project Access Enforcement
        # USR-002 manages PRJ-001, PRJ-004, PRJ-007; does NOT manage PRJ-002
        pm_headers = {"X-Test-User-ID": "USR-002"}

        # PM creating issue in another PM's project (PRJ-002) -> 403
        res = client.post("/api/issues", json={
            "project_id": "PRJ-002",
            "title": "Unauthorized PM Issue",
            "description": "Attempt to create defect in PRJ-002"
        }, headers=pm_headers)
        assert res.status_code == 403
        assert "within projects they manage" in res.get_json()["message"]
        print("  [PASS] Project Manager blocked from creating issues in unmanaged project with 403.")

        # Find an issue in PRJ-002
        with app.app_context():
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT issue_id FROM issues WHERE project_id = 'PRJ-002' LIMIT 1")
                prj2_issue_id = cur.fetchone()["issue_id"]

        # PM assigning issue in unmanaged project (PRJ-002) -> 403
        res = client.patch(f"/api/issues/{prj2_issue_id}/assign", json={"assigned_to": "USR-005"}, headers=pm_headers)
        assert res.status_code == 403
        assert "within projects they manage" in res.get_json()["message"]
        print("  [PASS] Project Manager blocked from assigning issues in unmanaged project with 403.")

        # PM changing status in unmanaged project (PRJ-002) -> 403
        res = client.patch(f"/api/issues/{prj2_issue_id}/status", json={"status": "In Progress"}, headers=pm_headers)
        assert res.status_code == 403
        print("  [PASS] Project Manager blocked from updating status in unmanaged project with 403.")

        # PM deleting issue in unmanaged project (PRJ-002) -> 403
        res = client.delete(f"/api/issues/{prj2_issue_id}", headers=pm_headers)
        assert res.status_code == 403
        print("  [PASS] Project Manager blocked from deleting issues in unmanaged project with 403.")

        # -------------------------------------------------------------
        # 8. Successful Full Issue Lifecycle (POST -> GET -> PUT -> PATCH -> DELETE)
        # -------------------------------------------------------------
        # A. Create Issue (POST /api/issues)
        create_res = client.post("/api/issues", json={
            "project_id": "PRJ-001",
            "title": "API Security Verification Defect",
            "description": "Automated test description for REST API verification.",
            "issue_type": "Bug",
            "severity": "High",
            "priority": "P1",
            "component": "API Gateway",
            "environment": "Staging",
            "steps_to_reproduce": "1. Send request\n2. Observe response",
            "expected_result": "Success response",
            "actual_result": "Error code",
            "business_impact": "Blocks integration tests"
        }, headers=auth_headers)
        assert create_res.status_code == 201, f"Expected 201, got {create_res.status_code}: {create_res.get_json()}"
        create_data = create_res.get_json()
        assert create_data["success"] is True
        created_id = create_data["issue_id"]
        assert created_id.startswith("BUG-")
        assert create_data["issue"]["status"] == "Open"
        assert create_data["issue"]["priority"] == "P1"
        assert create_data["issue"]["severity"] == "High"
        print(f"  [PASS] Issue created successfully via POST /api/issues (ID: {created_id}).")

        try:
            # B. Retrieve Issue (GET /api/issues/<id>)
            get_res = client.get(f"/api/issues/{created_id}")
            assert get_res.status_code == 200
            get_data = get_res.get_json()
            assert get_data["success"] is True
            assert get_data["issue"]["issue_id"] == created_id
            assert get_data["issue"]["title"] == "API Security Verification Defect"
            assert get_data["issue"]["component"] == "API Gateway"
            print("  [PASS] Issue retrieved successfully via GET /api/issues/<id>.")

            # C. Update Issue (PUT /api/issues/<id>)
            put_res = client.put(f"/api/issues/{created_id}", json={
                "title": "API Test Defect - Updated Title",
                "severity": "Critical",
                "priority": "P1",
                "component": "Backend REST Service"
            }, headers=auth_headers)
            assert put_res.status_code == 200
            put_data = put_res.get_json()
            assert put_data["success"] is True
            assert put_data["issue"]["title"] == "API Test Defect - Updated Title"
            assert put_data["issue"]["severity"] == "Critical"
            assert put_data["issue"]["component"] == "Backend REST Service"
            print("  [PASS] Issue updated successfully via PUT /api/issues/<id>.")

            # D. Assign Issue (PATCH /api/issues/<id>/assign)
            assign_res = client.patch(f"/api/issues/{created_id}/assign", json={
                "assigned_to": "USR-005"
            }, headers=auth_headers)
            assert assign_res.status_code == 200
            assign_data = assign_res.get_json()
            assert assign_data["success"] is True
            assert assign_data["assigned_to"] == "USR-005"
            assert assign_data["assignee_name"] == "Riley Chen"
            print("  [PASS] Issue assigned successfully via PATCH /api/issues/<id>/assign.")

            # E. Sequential Workflow Lifecycle Transitions (PATCH /api/issues/<id>/status)
            # Stage 1: Open -> In Progress
            s1_res = client.patch(f"/api/issues/{created_id}/status", json={"status": "In Progress"}, headers=auth_headers)
            assert s1_res.status_code == 200
            assert s1_res.get_json()["new_status"] == "In Progress"

            # Stage 2: In Progress -> Testing
            s2_res = client.patch(f"/api/issues/{created_id}/status", json={"status": "Testing"}, headers=auth_headers)
            assert s2_res.status_code == 200
            assert s2_res.get_json()["new_status"] == "Testing"

            # Stage 3: Testing -> Resolved
            s3_res = client.patch(f"/api/issues/{created_id}/status", json={
                "status": "Resolved",
                "resolution_summary": "Fixed by adding validation check."
            }, headers=auth_headers)
            assert s3_res.status_code == 200
            assert s3_res.get_json()["new_status"] == "Resolved"

            # Stage 4: Resolved -> Closed
            s4_res = client.patch(f"/api/issues/{created_id}/status", json={"status": "Closed"}, headers=auth_headers)
            assert s4_res.status_code == 200
            assert s4_res.get_json()["new_status"] == "Closed"
            print("  [PASS] Sequential lifecycle transitions verified via PATCH status (Open -> In Progress -> Testing -> Resolved -> Closed).")

            # F. Project-wise Issue Retrieval (GET /api/projects/<project_id>/issues)
            prj_res = client.get("/api/projects/PRJ-001/issues")
            assert prj_res.status_code == 200
            prj_data = prj_res.get_json()
            assert prj_data["success"] is True
            assert prj_data["project_id"] == "PRJ-001"
            assert prj_data["count"] > 0
            prj_issue_ids = [i["issue_id"] for i in prj_data["issues"]]
            assert created_id in prj_issue_ids
            print("  [PASS] Project-wise issue retrieval verified via GET /api/projects/<id>/issues.")

            # G. Filtering issues (GET /api/issues?status=Closed&priority=P1)
            filter_res = client.get(f"/api/issues?status=Closed&priority=P1&project_id=PRJ-001")
            assert filter_res.status_code == 200
            filter_data = filter_res.get_json()
            assert filter_data["success"] is True
            for iss in filter_data["issues"]:
                assert iss["status"] == "Closed"
                assert iss["priority"] == "P1"
                assert iss["project_id"] == "PRJ-001"
            print("  [PASS] Issue query parameter filtering verified (status, priority, project_id).")

        finally:
            # H. Delete Issue (DELETE /api/issues/<id>)
            del_res = client.delete(f"/api/issues/{created_id}", headers=auth_headers)
            assert del_res.status_code == 200
            assert del_res.get_json()["success"] is True
            print(f"  [PASS] Issue deleted successfully via DELETE /api/issues/<id>.")

            # Confirm 404 after deletion
            post_del_res = client.get(f"/api/issues/{created_id}")
            assert post_del_res.status_code == 404
            print("  [PASS] Confirm 404 after deletion.")

        print("\nALL REST API SECURITY & FUNCTIONAL TESTS PASSED CLEANLY! (100% success)")

    finally:
        # Restore admin password hash
        with app.app_context():
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET password_hash = %s WHERE user_id = 'USR-001'", 
                    (orig_admin_hash,)
                )
                conn.commit()

if __name__ == "__main__":
    test_api()
