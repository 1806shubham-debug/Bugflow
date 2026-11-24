import base64
import os
import sys

# Ensure app can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, get_db
from werkzeug.security import generate_password_hash


def test_analytics():
    print("=" * 70)
    print("Running BugFlow Milestone 3 - Module 3: Project Analytics Test Suite")
    print("=" * 70)

    app.config["TESTING"] = True
    client = app.test_client()

    # Query actual database baseline counts dynamically (supports clean 750-record or live 756-record DB)
    with app.app_context():
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    COUNT(*) AS total_issues,
                    COUNT(*) FILTER (WHERE status = 'Open') AS open_issues,
                    COUNT(*) FILTER (WHERE status = 'In Progress') AS in_progress_issues,
                    COUNT(*) FILTER (WHERE status = 'Testing') AS testing_issues,
                    COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved_issues,
                    COUNT(*) FILTER (WHERE status = 'Closed') AS closed_issues,
                    COUNT(*) FILTER (WHERE status NOT IN ('Resolved', 'Closed')) AS pending_issues
                FROM issues;
            """)
            db_expected = cur.fetchone()

            cur.execute("SELECT COUNT(*) AS cnt FROM issues WHERE component IS NULL OR TRIM(component) = ''")
            expected_unassigned = cur.fetchone()["cnt"]

            cur.execute("SELECT password_hash FROM users WHERE user_id = 'USR-001'")
            orig_admin_hash = cur.fetchone()["password_hash"]
            cur.execute("SELECT password_hash FROM users WHERE user_id = 'USR-002'")
            orig_pm_hash = cur.fetchone()["password_hash"]

            cur.execute(
                "UPDATE users SET password_hash = %s WHERE user_id = 'USR-001'",
                (generate_password_hash("AdminPass123!"),)
            )
            cur.execute(
                "UPDATE users SET password_hash = %s WHERE user_id = 'USR-002'",
                (generate_password_hash("PMPass123!"),)
            )
            conn.commit()

    try:
        # -----------------------------------------------------------------
        # TEST 11: Unauthorized requests (unauthenticated) return 401
        # -----------------------------------------------------------------
        print("\n--- Test 11: Unauthorized Requests (401 Verification) ---")
        endpoints = [
            "/api/analytics/overview",
            "/api/analytics/projects",
            "/api/analytics/projects/PRJ-001",
            "/api/analytics/trends",
            "/api/analytics/modules"
        ]
        for ep in endpoints:
            res = client.get(ep)
            assert res.status_code == 401, f"Expected 401 for {ep}, got {res.status_code}"
            data = res.get_json()
            assert data["success"] is False
            assert data["error"] == "Unauthorized"
        print("  [PASS] All 5 analytics endpoints strictly reject unauthenticated requests with 401.")

        # -----------------------------------------------------------------
        # Log in Admin client (USR-001)
        # -----------------------------------------------------------------
        client.get("/login")
        with client.session_transaction() as sess:
            csrf_token = sess["csrf_token"]
        login_res = client.post("/login", data={
            "csrf_token": csrf_token,
            "email": "alex.morgan@example.org",
            "password": "AdminPass123!"
        }, follow_redirects=True)
        assert login_res.status_code == 200

        # -----------------------------------------------------------------
        # TEST 1: Total issue count matches database baseline
        # -----------------------------------------------------------------
        print("\n--- Test 1: Total Issue Count Baseline ---")
        overview_res = client.get("/api/analytics/overview")
        assert overview_res.status_code == 200
        ov_data = overview_res.get_json()
        assert ov_data["success"] is True
        total_issues = ov_data["summary"]["total_issues"]
        assert total_issues == db_expected["total_issues"], f"Expected {db_expected['total_issues']} total issues, got {total_issues}"
        print(f"  [PASS] Total issue count matches verified database baseline: {total_issues}")

        # -----------------------------------------------------------------
        # TEST 2: Status-wise counts (Open, In Progress, Testing, Resolved, Closed)
        # -----------------------------------------------------------------
        print("\n--- Test 2: Status-Wise Breakdown Counts ---")
        s = ov_data["summary"]
        assert s["open_issues"] == db_expected["open_issues"]
        assert s["in_progress_issues"] == db_expected["in_progress_issues"]
        assert s["testing_issues"] == db_expected["testing_issues"]
        assert s["resolved_issues"] == db_expected["resolved_issues"]
        assert s["closed_issues"] == db_expected["closed_issues"]
        sum_status = (s["open_issues"] + s["in_progress_issues"] + s["testing_issues"] +
                      s["resolved_issues"] + s["closed_issues"])
        assert sum_status == total_issues, f"Status sum {sum_status} != total {total_issues}"
        print(f"  [PASS] Status breakdown verified: Open={s['open_issues']}, In Progress={s['in_progress_issues']}, Testing={s['testing_issues']}, Resolved={s['resolved_issues']}, Closed={s['closed_issues']} (Sum={sum_status}).")

        # -----------------------------------------------------------------
        # TEST 3: Pending and resolution calculations
        # -----------------------------------------------------------------
        print("\n--- Test 3: Pending Issues and Resolution Percentage ---")
        expected_pending = s["open_issues"] + s["in_progress_issues"] + s["testing_issues"]
        assert s["pending_issues"] == expected_pending == db_expected["pending_issues"]
        resolved_total = s["resolved_issues"] + s["closed_issues"]
        assert resolved_total == (db_expected["resolved_issues"] + db_expected["closed_issues"])
        expected_pct = round((resolved_total * 100.0) / total_issues, 2)
        assert s["resolution_percentage"] == expected_pct
        print(f"  [PASS] Pending issues = {s['pending_issues']}, Resolved/Closed = {resolved_total}, Resolution % = {s['resolution_percentage']}%.")

        # -----------------------------------------------------------------
        # TEST 4: Project-wise statistics
        # -----------------------------------------------------------------
        print("\n--- Test 4: Project-Wise Analytics ---")
        proj_res = client.get("/api/analytics/projects")
        assert proj_res.status_code == 200
        p_data = proj_res.get_json()
        assert p_data["success"] is True
        assert p_data["count"] == 8, f"Expected 8 projects, got {p_data['count']}"
        projects = p_data["projects"]
        sum_proj_issues = sum(p["total_issues"] for p in projects)
        sum_proj_pending = sum(p["pending_issues"] for p in projects)
        sum_proj_resolved = sum(p["resolved_issues"] + p["closed_issues"] for p in projects)
        assert sum_proj_issues == total_issues
        assert sum_proj_pending == s["pending_issues"]
        assert sum_proj_resolved == resolved_total

        for p in projects:
            assert p["project_id"] in [f"PRJ-00{i}" for i in range(1, 9)]
            assert p["total_issues"] == p["pending_issues"] + p["resolved_issues"] + p["closed_issues"]
            assert p["average_resolution_hours"] >= 0.0
            assert p["average_resolution_days"] >= 0.0
            calc_pct = round(((p["resolved_issues"] + p["closed_issues"]) * 100.0) / p["total_issues"], 2)
            assert p["resolution_percentage"] == calc_pct
        print(f"  [PASS] All 8 projects verified: total issues = {sum_proj_issues}, pending = {sum_proj_pending}, resolved = {sum_proj_resolved}.")

        # -----------------------------------------------------------------
        # TEST 5: Average resolution time calculation (hours and days)
        # -----------------------------------------------------------------
        print("\n--- Test 5: Average Resolution Time Metrics ---")
        rt = ov_data["resolution_time"]
        assert rt["sample_size"] == resolved_total
        assert rt["average_resolution_hours"] >= 0.0
        assert rt["average_resolution_days"] >= 0.0
        calc_days = round(rt["average_resolution_hours"] / 24.0, 2)
        assert rt["average_resolution_days"] == calc_days
        print(f"  [PASS] Resolution time metrics: sample={rt['sample_size']}, avg_hours={rt['average_resolution_hours']}h, avg_days={rt['average_resolution_days']}d.")

        # -----------------------------------------------------------------
        # TEST 6: Monthly defect trends (reported vs resolved)
        # -----------------------------------------------------------------
        print("\n--- Test 6: Monthly Defect Trends ---")
        trends_res = client.get("/api/analytics/trends")
        assert trends_res.status_code == 200
        tr_data = trends_res.get_json()
        assert tr_data["success"] is True
        assert tr_data["count"] > 0
        trends = tr_data["trends"]
        sum_reported = sum(t["reported_count"] for t in trends)
        sum_resolved = sum(t["resolved_count"] for t in trends)
        assert sum_reported == total_issues
        assert sum_resolved == resolved_total
        # Verify chronological order
        months = [t["month"] for t in trends]
        assert months == sorted(months), "Trends months are not in chronological order"
        print(f"  [PASS] Monthly trends verified: {len(trends)} months, reported={sum_reported}, resolved={sum_resolved}, chronological order confirmed.")

        # -----------------------------------------------------------------
        # TEST 7: Component / module-wise statistics
        # -----------------------------------------------------------------
        print("\n--- Test 7: Module-Wise Defect Analysis ---")
        mod_res = client.get("/api/analytics/modules")
        assert mod_res.status_code == 200
        m_data = mod_res.get_json()
        assert m_data["success"] is True
        assert m_data["count"] > 0
        modules = m_data["modules"]
        sum_mod_defects = sum(m["total_defects"] for m in modules)
        assert sum_mod_defects == total_issues
        print(f"  [PASS] Module-wise analysis verified: {len(modules)} modules covering all {sum_mod_defects} defects.")

        # -----------------------------------------------------------------
        # TEST 8: Severity distribution within module breakdown
        # -----------------------------------------------------------------
        print("\n--- Test 8: Severity Distribution in Modules ---")
        for m in modules:
            sev = m["severity_breakdown"]
            sev_sum = sev["critical"] + sev["high"] + sev["medium"] + sev["low"]
            assert sev_sum == m["total_defects"], f"Module {m['module_name']} severity sum {sev_sum} != {m['total_defects']}"
        print("  [PASS] Severity distributions (Critical, High, Medium, Low) match module totals 100%.")

        # -----------------------------------------------------------------
        # TEST 9: Handling of NULL and empty component values ('Unassigned')
        # -----------------------------------------------------------------
        print("\n--- Test 9: NULL and Empty Component Values Handled Gracefully ---")
        if expected_unassigned > 0:
            unassigned_module = next((m for m in modules if m["module_name"] == "Unassigned"), None)
            assert unassigned_module is not None, "'Unassigned' module not found in modules"
            assert unassigned_module["total_defects"] == expected_unassigned
            print(f"  [PASS] {expected_unassigned} issues with NULL/empty components grouped into 'Unassigned' module safely.")
        else:
            print("  [PASS] No NULL/empty component issues found.")
        # Ensure no None or blank string module names
        for m in modules:
            assert m["module_name"] and m["module_name"].strip() != ""

        # -----------------------------------------------------------------
        # TEST 10: Invalid project ID returns 404
        # -----------------------------------------------------------------
        print("\n--- Test 10: Non-Existent Project ID Returns 404 ---")
        bad_endpoints = [
            "/api/analytics/projects/PRJ-INVALID-999",
            "/api/analytics/overview?project_id=PRJ-INVALID-999",
            "/api/analytics/trends?project_id=PRJ-INVALID-999",
            "/api/analytics/modules?project_id=PRJ-INVALID-999"
        ]
        for ep in bad_endpoints:
            res = client.get(ep)
            assert res.status_code == 404, f"Expected 404 for {ep}, got {res.status_code}"
            data = res.get_json()
            assert data["success"] is False
            assert data["error"] == "Not Found"
        print("  [PASS] Non-existent project IDs consistently return 404 Not Found.")

        # -----------------------------------------------------------------
        # TEST 12: Project Manager cross-project access rejection (403)
        # -----------------------------------------------------------------
        print("\n--- Test 12: Role-Based Authorization & PM Cross-Project Restrictions ---")
        # Log out Admin and log in USR-002 (Project Manager)
        client.get("/logout")
        client.get("/login")
        with client.session_transaction() as sess:
            csrf_token = sess["csrf_token"]
        pm_login = client.post("/login", data={
            "csrf_token": csrf_token,
            "email": "jordan.lee@example.org",
            "password": "PMPass123!"
        }, follow_redirects=True)
        assert pm_login.status_code == 200

        # Query managed and unmanaged projects for USR-002
        with app.app_context():
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("SELECT project_id FROM projects WHERE project_manager_id = 'USR-002' ORDER BY project_id")
                managed_pids = [r["project_id"] for r in cur.fetchall()]
                cur.execute("SELECT project_id FROM projects WHERE project_manager_id != 'USR-002' ORDER BY project_id LIMIT 1")
                unmanaged_pid = cur.fetchone()["project_id"]

        # Attempt to access unmanaged project endpoints as USR-002 -> 403 Forbidden
        pm_forbidden_endpoints = [
            f"/api/analytics/projects/{unmanaged_pid}",
            f"/api/analytics/overview?project_id={unmanaged_pid}",
            f"/api/analytics/trends?project_id={unmanaged_pid}",
            f"/api/analytics/modules?project_id={unmanaged_pid}"
        ]
        for ep in pm_forbidden_endpoints:
            res = client.get(ep)
            assert res.status_code == 403, f"Expected 403 for {ep}, got {res.status_code}"
            data = res.get_json()
            assert data["success"] is False
            assert data["error"] == "Forbidden"
        print(f"  [PASS] Project Manager (USR-002) is strictly forbidden (403) from accessing unmanaged project ({unmanaged_pid}).")

        # USR-002 accessing their own project -> 200 OK
        pm_own_pid = managed_pids[0]
        pm_own_res = client.get(f"/api/analytics/projects/{pm_own_pid}")
        assert pm_own_res.status_code == 200
        assert pm_own_res.get_json()["project"]["project_id"] == pm_own_pid
        print(f"  [PASS] Project Manager (USR-002) successfully accesses managed project ({pm_own_pid}) with 200 OK.")

        # USR-002 calling /api/analytics/projects -> only sees their managed projects
        pm_proj_res = client.get("/api/analytics/projects")
        assert pm_proj_res.status_code == 200
        pm_proj_data = pm_proj_res.get_json()
        assert pm_proj_data["count"] == len(managed_pids)
        assert {p["project_id"] for p in pm_proj_data["projects"]} == set(managed_pids)
        print(f"  [PASS] Project Manager list endpoint returns only managed projects ({set(managed_pids)}).")

        # -----------------------------------------------------------------
        # TEST 13: Defect density reported as available: false with explanation
        # -----------------------------------------------------------------
        print("\n--- Test 13: Defect Density Status ---")
        client.get("/logout")
        client.get("/login")
        with client.session_transaction() as sess:
            csrf_token = sess["csrf_token"]
        client.post("/login", data={
            "csrf_token": csrf_token,
            "email": "alex.morgan@example.org",
            "password": "AdminPass123!"
        }, follow_redirects=True)

        dd_res = client.get("/api/analytics/overview")
        assert dd_res.status_code == 200
        dd_data = dd_res.get_json()
        assert "defect_density" in dd_data
        dd = dd_data["defect_density"]
        assert dd["available"] is False, "Defect density should be reported as available: False"
        assert "KLOC" in dd["reason"] or "LOC" in dd["reason"] or "code-size" in dd["reason"].lower()
        print(f"  [PASS] Defect density reported as available: false with honest reason: '{dd['reason']}'.")

        print("\n" + "=" * 70)
        print("ALL 13 ANALYTICS ENGINE TEST SCENARIOS PASSED WITH 100% SUCCESS!")
        print("=" * 70)

    finally:
        # Restore original password hashes
        with app.app_context():
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password_hash = %s WHERE user_id = 'USR-001'", (orig_admin_hash,))
                cur.execute("UPDATE users SET password_hash = %s WHERE user_id = 'USR-002'", (orig_pm_hash,))
                conn.commit()


if __name__ == "__main__":
    test_analytics()
