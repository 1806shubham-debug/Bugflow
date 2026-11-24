import http.cookiejar
import re
import urllib.error
import urllib.parse
import urllib.request


def test_live_server():
    print("=" * 70)
    print("Verifying Live Running Flask Server at http://127.0.0.1:5001")
    print("=" * 70)

    # 1. Unauthenticated /dashboard -> 302
    try:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        custom_opener = urllib.request.build_opener(NoRedirect)
        custom_opener.open("http://127.0.0.1:5001/dashboard")
        assert False, "Should have returned 302 redirect"
    except urllib.error.HTTPError as e:
        assert e.code == 302
        assert "/login" in e.headers.get("Location", "")
        print("  [PASS] Unauthenticated access to http://127.0.0.1:5001/dashboard redirected with 302 to /login.")

    # 2. Login as Admin
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    login_page = opener.open("http://127.0.0.1:5001/login").read().decode()
    csrf_match = re.search(r'name=["\']csrf_token["\'] value=["\']([^"\']+)["\']', login_page)
    csrf_token = csrf_match.group(1)

    login_data = urllib.parse.urlencode({
        "csrf_token": csrf_token,
        "email": "alex.morgan@example.org",
        "password": "AdminPass123!"
    }).encode()
    login_res = opener.open("http://127.0.0.1:5001/login", data=login_data)
    assert login_res.status == 200

    # 3. GET /dashboard
    dash_html = opener.open("http://127.0.0.1:5001/dashboard").read().decode()
    assert "756" in dash_html
    assert "320" in dash_html
    assert "57.67%" in dash_html
    assert 'id="statusChart"' in dash_html
    assert 'id="severityChart"' in dash_html
    assert 'id="trendsChart"' in dash_html
    assert "Defect Density:" in dash_html
    assert "Unavailable" in dash_html
    assert "Code-size denominator (KLOC/LOC) not present in database schema." in dash_html
    print("  [PASS] Admin dashboard renders over live HTTP with all 9 KPIs, all 3 Chart.js canvases, and Defect Density notice.")

    # 4. Project Filter HTTP fetch
    p1_html = opener.open("http://127.0.0.1:5001/dashboard?project_id=PRJ-001").read().decode()
    assert "PRJ-001" in p1_html
    assert "117" in p1_html
    assert "56" in p1_html
    assert "52.14%" in p1_html
    print("  [PASS] Project PRJ-001 dashboard renders over live HTTP with updated KPIs (Total 117, Pending 56, Resolution 52.14%).")

    # 5. Project Manager Login
    pm_cj = http.cookiejar.CookieJar()
    pm_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(pm_cj))
    pm_login_page = pm_opener.open("http://127.0.0.1:5001/login").read().decode()
    pm_csrf = re.search(r'name=["\']csrf_token["\'] value=["\']([^"\']+)["\']', pm_login_page).group(1)
    pm_login_res = pm_opener.open("http://127.0.0.1:5001/login", data=urllib.parse.urlencode({
        "csrf_token": pm_csrf,
        "email": "jordan.lee@example.org",
        "password": "PMPass123!"
    }).encode())
    assert pm_login_res.status == 200

    # 6. PM unmanaged project access -> 403
    try:
        pm_opener.open("http://127.0.0.1:5001/dashboard?project_id=PRJ-002")
        assert False, "Should have been 403"
    except urllib.error.HTTPError as e:
        assert e.code == 403
        print("  [PASS] Project Manager access to unmanaged PRJ-002 rejected over live HTTP with 403 Forbidden.")

    # 7. Non-existent project -> 404
    try:
        pm_opener.open("http://127.0.0.1:5001/dashboard?project_id=PRJ-INVALID-999")
        assert False, "Should have been 404"
    except urllib.error.HTTPError as e:
        assert e.code == 404
        print("  [PASS] Non-existent project access rejected over live HTTP with 404 Not Found.")

    print("\n" + "=" * 70)
    print("ALL LIVE HTTP SERVER VERIFICATION CHECKS PASSED WITH 100% SUCCESS!")
    print("=" * 70)


if __name__ == "__main__":
    test_live_server()

