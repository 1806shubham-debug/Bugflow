import json
import os
import re
import sys

# Ensure app can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, get_db
from werkzeug.security import generate_password_hash


def get_text_by_id(html, elem_id):
    """Extract text inside an HTML element with the given id using standard library regex."""
    m = re.search(r'id=["\']' + re.escape(elem_id) + r'["\'][^>]*>(.*?)</', html, re.DOTALL)
    if not m:
        return ""
    # Strip nested HTML tags
    clean = re.sub(r'<[^>]+>', ' ', m.group(1))
    return ' '.join(clean.split())


def test_dashboard():
    print("=" * 70)
    print("Running BugFlow Milestone 3 - Module 4: Admin Dashboard & Visualizations Test Suite")
    print("=" * 70)

    app.config["TESTING"] = True
    client = app.test_client()

    # Setup test credentials for USR-001 (Admin) and USR-002 (Project Manager)
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
                    COUNT(*) FILTER (WHERE status NOT IN ('Resolved', 'Closed')) AS pending_issues,
                    COUNT(*) FILTER (WHERE severity = 'Critical') AS critical_issues,
                    COUNT(*) FILTER (WHERE severity = 'High') AS high_issues,
                    COUNT(*) FILTER (WHERE severity = 'Medium') AS medium_issues,
                    COUNT(*) FILTER (WHERE severity = 'Low') AS low_issues
                FROM issues;
            """)
            db_expected = cur.fetchone()

            cur.execute("""
                SELECT 
                    COUNT(*) AS total_issues,
                    COUNT(*) FILTER (WHERE status = 'Open') AS open_issues,
                    COUNT(*) FILTER (WHERE status = 'In Progress') AS in_progress_issues,
                    COUNT(*) FILTER (WHERE status = 'Testing') AS testing_issues,
                    COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved_issues,
                    COUNT(*) FILTER (WHERE status = 'Closed') AS closed_issues,
                    COUNT(*) FILTER (WHERE status NOT IN ('Resolved', 'Closed')) AS pending_issues
                FROM issues
                WHERE project_id = 'PRJ-001';
            """)
            db_prj1_expected = cur.fetchone()

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
        # 0. Unauthenticated Access -> Redirect to Login
        # -----------------------------------------------------------------
        print("\n--- Pre-check: Unauthenticated Dashboard Access ---")
        unauth_res = client.get("/dashboard", follow_redirects=False)
        assert unauth_res.status_code == 302, f"Expected 302 redirect, got {unauth_res.status_code}"
        assert "/login" in unauth_res.headers["Location"]
        print("  [PASS] Unauthenticated access to /dashboard safely redirects to /login.")

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

        # Fetch Reference API responses for verification
        api_ov_res = client.get("/api/analytics/overview")
        assert api_ov_res.status_code == 200
        api_ov = api_ov_res.get_json()

        api_tr_res = client.get("/api/analytics/trends")
        assert api_tr_res.status_code == 200
        api_tr = api_tr_res.get_json()

        # Load Dashboard HTML
        dash_res = client.get("/dashboard")
        assert dash_res.status_code == 200
        html = dash_res.data.decode("utf-8")

        # -----------------------------------------------------------------
        # TEST 1: All 9 KPI values match analytics API responses
        # -----------------------------------------------------------------
        print("\n--- Test 1: All 9 KPI Values Match Analytics API Responses ---")
        s = api_ov["summary"]
        rt = api_ov["resolution_time"]

        kpi_total = get_text_by_id(html, "kpiTotal")
        kpi_pending = get_text_by_id(html, "kpiPending")
        kpi_res_rate = get_text_by_id(html, "kpiResolutionRate")
        kpi_open = get_text_by_id(html, "kpiOpen")
        kpi_in_progress = get_text_by_id(html, "kpiInProgress")
        kpi_testing = get_text_by_id(html, "kpiTesting")
        kpi_resolved = get_text_by_id(html, "kpiResolved")
        kpi_closed = get_text_by_id(html, "kpiClosed")
        kpi_avg_time = get_text_by_id(html, "kpiAvgTime")

        expected_res_rate = round(
            ((db_expected["resolved_issues"] + db_expected["closed_issues"]) / db_expected["total_issues"] * 100), 2
        ) if db_expected["total_issues"] else 0.0

        assert int(kpi_total) == s["total_issues"] == db_expected["total_issues"], f"Total {kpi_total} != {s['total_issues']}"
        assert int(kpi_pending) == s["pending_issues"] == db_expected["pending_issues"], f"Pending {kpi_pending} != {s['pending_issues']}"
        assert float(kpi_res_rate.replace("%", "")) == s["resolution_percentage"] == expected_res_rate
        assert int(kpi_open) == s["open_issues"] == db_expected["open_issues"]
        assert int(kpi_in_progress) == s["in_progress_issues"] == db_expected["in_progress_issues"]
        assert int(kpi_testing) == s["testing_issues"] == db_expected["testing_issues"]
        assert int(kpi_resolved) == s["resolved_issues"] == db_expected["resolved_issues"]
        assert int(kpi_closed) == s["closed_issues"] == db_expected["closed_issues"]
        assert f"{rt['average_resolution_hours']}h" in kpi_avg_time
        assert f"({rt['average_resolution_days']}d)" in kpi_avg_time

        print(f"  [PASS] Total: {kpi_total}, Pending: {kpi_pending}, Resolution Rate: {kpi_res_rate}")
        print(f"  [PASS] Status breakdown: Open={kpi_open}, InProgress={kpi_in_progress}, Testing={kpi_testing}, Resolved={kpi_resolved}, Closed={kpi_closed}")
        print(f"  [PASS] Avg Resolution Time: {kpi_avg_time} matches API ({rt['average_resolution_hours']}h / {rt['average_resolution_days']}d)")

        # -----------------------------------------------------------------
        # TEST 2: Status chart totals match total issues
        # -----------------------------------------------------------------
        print("\n--- Test 2: Status Chart Totals Match Total Issues ---")
        m_seed = re.search(r'<script id="serverSeedData"[^>]*>(.*?)</script>', html, re.DOTALL)
        assert m_seed is not None, "serverSeedData script element not found in HTML"
        seed_data = json.loads(m_seed.group(1))
        seed_kpis = seed_data["kpis"]

        status_sum = (
            seed_kpis["open"] +
            seed_kpis["in_progress"] +
            seed_kpis["testing"] +
            seed_kpis["resolved"] +
            seed_kpis["closed"]
        )
        assert status_sum == seed_kpis["total"] == db_expected["total_issues"]
        assert re.search(r'<canvas[^>]*id=["\']statusChart["\']', html) is not None
        print(f"  [PASS] Status breakdown sum ({status_sum}) matches total issues ({seed_kpis['total']}) 100%.")

        # -----------------------------------------------------------------
        # TEST 3: Severity chart totals match total issues
        # -----------------------------------------------------------------
        print("\n--- Test 3: Severity Chart Totals Match Total Issues ---")
        sev_sum = (
            seed_kpis["critical"] +
            seed_kpis["high"] +
            seed_kpis["medium"] +
            seed_kpis["low"]
        )
        assert sev_sum == seed_kpis["total"] == db_expected["total_issues"]
        assert seed_kpis["critical"] == db_expected["critical_issues"]
        assert seed_kpis["high"] == db_expected["high_issues"]
        assert seed_kpis["medium"] == db_expected["medium_issues"]
        assert seed_kpis["low"] == db_expected["low_issues"]
        assert re.search(r'<canvas[^>]*id=["\']severityChart["\']', html) is not None
        print(f"  [PASS] Severity breakdown sum ({sev_sum}) matches total issues ({seed_kpis['total']}) 100%.")

        # -----------------------------------------------------------------
        # TEST 4: Monthly trends match the analytics endpoint
        # -----------------------------------------------------------------
        print("\n--- Test 4: Monthly Trends Match Analytics Endpoint ---")
        trends = seed_data["trends"]
        assert len(trends) == len(api_tr["trends"])
        sum_tr_reported = sum(t["reported_count"] for t in trends)
        sum_tr_resolved = sum(t["resolved_count"] for t in trends)
        assert sum_tr_reported == db_expected["total_issues"]
        assert sum_tr_resolved == sum(t["resolved_count"] for t in api_tr["trends"])
        assert re.search(r'<canvas[^>]*id=["\']trendsChart["\']', html) is not None
        print(f"  [PASS] Monthly trends data ({len(trends)} months) reported={sum_tr_reported}, resolved={sum_tr_resolved} matches API.")

        # -----------------------------------------------------------------
        # TEST 5: Project filtering updates all dashboard components
        # -----------------------------------------------------------------
        print("\n--- Test 5: Project Filtering Updates Dashboard Components ---")
        # Fetch PRJ-001 overview API
        prj1_ov_res = client.get("/api/analytics/overview?project_id=PRJ-001")
        assert prj1_ov_res.status_code == 200
        prj1_ov = prj1_ov_res.get_json()
        p1_s = prj1_ov["summary"]
        p1_rt = prj1_ov["resolution_time"]
        p1_sev = prj1_ov["severity_breakdown"]

        # Fetch PRJ-001 dashboard HTML
        prj1_dash_res = client.get("/dashboard?project_id=PRJ-001")
        assert prj1_dash_res.status_code == 200
        p1_html = prj1_dash_res.data.decode("utf-8")

        # Verify dropdown selection
        assert re.search(r'<option[^>]*value=["\']PRJ-001["\'][^>]*selected', p1_html) is not None

        # Verify all KPI values update to PRJ-001 metrics
        p1_total = int(get_text_by_id(p1_html, "kpiTotal"))
        p1_pending = int(get_text_by_id(p1_html, "kpiPending"))
        p1_rate = float(get_text_by_id(p1_html, "kpiResolutionRate").replace("%", ""))
        p1_open = int(get_text_by_id(p1_html, "kpiOpen"))
        p1_prog = int(get_text_by_id(p1_html, "kpiInProgress"))
        p1_test = int(get_text_by_id(p1_html, "kpiTesting"))
        p1_res = int(get_text_by_id(p1_html, "kpiResolved"))
        p1_closed = int(get_text_by_id(p1_html, "kpiClosed"))

        expected_p1_rate = round(
            ((db_prj1_expected["resolved_issues"] + db_prj1_expected["closed_issues"]) / db_prj1_expected["total_issues"] * 100), 2
        ) if db_prj1_expected["total_issues"] else 0.0

        assert p1_total == p1_s["total_issues"] == db_prj1_expected["total_issues"]
        assert p1_pending == p1_s["pending_issues"] == db_prj1_expected["pending_issues"]
        assert p1_rate == p1_s["resolution_percentage"] == expected_p1_rate
        assert p1_open == p1_s["open_issues"] == db_prj1_expected["open_issues"]
        assert p1_prog == p1_s["in_progress_issues"] == db_prj1_expected["in_progress_issues"]
        assert p1_test == p1_s["testing_issues"] == db_prj1_expected["testing_issues"]
        assert p1_res == p1_s["resolved_issues"] == db_prj1_expected["resolved_issues"]
        assert p1_closed == p1_s["closed_issues"] == db_prj1_expected["closed_issues"]

        # Verify seed data status and severity sum equals project total
        m_p1_seed = re.search(r'<script id="serverSeedData"[^>]*>(.*?)</script>', p1_html, re.DOTALL)
        p1_seed = json.loads(m_p1_seed.group(1))
        p1_kpis = p1_seed["kpis"]
        p1_status_sum = p1_kpis["open"] + p1_kpis["in_progress"] + p1_kpis["testing"] + p1_kpis["resolved"] + p1_kpis["closed"]
        p1_sev_sum = p1_kpis["critical"] + p1_kpis["high"] + p1_kpis["medium"] + p1_kpis["low"]
        assert p1_status_sum == db_prj1_expected["total_issues"]
        assert p1_sev_sum == db_prj1_expected["total_issues"]

        print(f"  [PASS] PRJ-001 filter correctly updated KPIs: Total={p1_total}, Pending={p1_pending}, Resolution={p1_rate}%.")
        print(f"  [PASS] PRJ-001 Status Sum ({p1_status_sum}) and Severity Sum ({p1_sev_sum}) match project total ({db_prj1_expected['total_issues']}).")

        # -----------------------------------------------------------------
        # TEST 6: Unauthorized project selection is rejected (403 & 404)
        # -----------------------------------------------------------------
        print("\n--- Test 6: Role-Based Authorization & PM Project Restrictions ---")
        # Log out Admin and log in USR-002 (Project Manager)
        client.get("/logout")
        client.get("/login")
        with client.session_transaction() as sess:
            csrf_token = sess["csrf_token"]
        client.post("/login", data={
            "csrf_token": csrf_token,
            "email": "jordan.lee@example.org",
            "password": "PMPass123!"
        }, follow_redirects=True)

        # USR-002 attempts to access unmanaged PRJ-002 -> 403 Forbidden
        pm_unauth_res = client.get("/dashboard?project_id=PRJ-002")
        assert pm_unauth_res.status_code == 403, f"Expected 403, got {pm_unauth_res.status_code}"
        print("  [PASS] Project Manager (USR-002) accessing unmanaged project (PRJ-002) is strictly rejected with 403.")

        # Non-existent project -> 404 Not Found
        pm_404_res = client.get("/dashboard?project_id=PRJ-INVALID-999")
        assert pm_404_res.status_code == 404
        print("  [PASS] Non-existent project ID returns 404 Not Found.")

        # USR-002 accesses managed project PRJ-001 -> 200 OK
        pm_auth_res = client.get("/dashboard?project_id=PRJ-001")
        assert pm_auth_res.status_code == 200
        print("  [PASS] Project Manager (USR-002) successfully accesses managed project PRJ-001 with 200 OK.")

        # Check PM dropdown options: only managed projects and no 'All Projects (System-wide)'
        pm_dash_res = client.get("/dashboard")
        assert pm_dash_res.status_code == 200
        pm_html = pm_dash_res.data.decode("utf-8")
        pm_options = re.findall(r'<option[^>]*value=["\']([^"\']*)["\'][^>]*>(.*?)</option>', pm_html, re.DOTALL)
        pm_opt_vals = [opt[0] for opt in pm_options]
        pm_opt_texts = [opt[1].strip() for opt in pm_options]

        # Must not contain unmanaged projects
        assert "PRJ-002" not in pm_opt_vals
        assert "PRJ-003" not in pm_opt_vals
        assert "PRJ-005" not in pm_opt_vals
        assert "PRJ-006" not in pm_opt_vals
        assert "PRJ-008" not in pm_opt_vals
        # Must contain only their 3 managed projects
        assert "PRJ-001" in pm_opt_vals
        assert "PRJ-004" in pm_opt_vals
        assert "PRJ-007" in pm_opt_vals
        # Must not contain "All Projects (System-wide)"
        assert not any("System-wide" in t for t in pm_opt_texts)
        assert any("All Managed Projects" in t for t in pm_opt_texts)
        print("  [PASS] Project Manager dropdown is strictly scoped to managed projects ({'PRJ-001', 'PRJ-004', 'PRJ-007'}).")

        # -----------------------------------------------------------------
        # TEST 7: Empty datasets render safely
        # -----------------------------------------------------------------
        print("\n--- Test 7: Empty Datasets Render Safely Without Crashes ---")
        with app.test_request_context():
            from flask import render_template
            empty_kpis = {
                "total": 0, "open": 0, "in_progress": 0, "testing": 0,
                "resolved": 0, "closed": 0, "pending": 0,
                "resolution_percentage": 0.0,
                "avg_resolution_hours": 0.0, "avg_resolution_days": 0.0,
                "critical": 0, "high": 0, "medium": 0, "low": 0,
                "unassigned": 0, "resolved_all": 0
            }
            empty_html = render_template(
                "dashboard.html",
                active_page="dashboard",
                kpis=empty_kpis,
                stats=empty_kpis,
                selected_project_id="",
                accessible_projects=[],
                role_scope_msg="Empty Scope Test",
                trends_data=[],
                modules_data=[],
                project_stats=[],
                recent_issues=[],
                defect_density={"available": False, "reason": "Code-size denominator (KLOC/LOC) not present in database schema."},
                today_date="Nov 24, 2026"
            )
            assert get_text_by_id(empty_html, "kpiTotal") == "0"
            assert get_text_by_id(empty_html, "kpiResolutionRate") == "0.0%"
            assert "No module data recorded for this selection." in empty_html
            assert "No recent issues found." in empty_html
        print("  [PASS] Empty datasets render safely with 0 counts and clean empty state messaging.")

        # -----------------------------------------------------------------
        # TEST 8: Defect density unavailable state is displayed correctly
        # -----------------------------------------------------------------
        print("\n--- Test 8: Defect Density Status Banner Verification ---")
        client.get("/logout")
        client.get("/login")
        with client.session_transaction() as sess:
            csrf_token = sess["csrf_token"]
        client.post("/login", data={
            "csrf_token": csrf_token,
            "email": "alex.morgan@example.org",
            "password": "AdminPass123!"
        }, follow_redirects=True)

        admin_dash = client.get("/dashboard")
        admin_html = admin_dash.data.decode("utf-8")
        assert 'id="defectDensityAlert"' in admin_html
        badge_text = get_text_by_id(admin_html, "defectDensityBadge")
        assert badge_text == "Unavailable"
        reason_text = get_text_by_id(admin_html, "defectDensityReason")
        assert "KLOC" in reason_text or "LOC" in reason_text or "Code-size" in reason_text
        print(f"  [PASS] Defect density notice displays 'Unavailable' with honest reason: '{reason_text}'.")

        print("\n" + "=" * 70)
        print("ALL 8 DASHBOARD VISUALIZATIONS TEST SCENARIOS PASSED WITH 100% SUCCESS!")
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
    test_dashboard()
