"""
BugFlow Milestone 3 Test Runner
Runs the 5 in-process test suites in a safe, deterministic sequence using Python standard library.
(Excludes tests/test_live_server.py which requires an external server daemon).
"""
import importlib
import os
import sys
import time
import traceback

# Ensure workspace root is in sys.path
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

SUITES = [
    ("Milestone 3 Module 3: Analytics Engine", "tests.test_analytics", "test_analytics"),
    ("Milestone 3 Module 4: Admin Dashboard & Visualizations", "tests.test_dashboard", "test_dashboard"),
    ("Milestone 3 Module 2: GitHub Webhook Integration", "tests.test_github", "test_github"),
    ("Milestone 3 Module 1: REST API Security & Functional", "tests.test_api", "test_api"),
    ("Milestones 1 & 2: Core Web Application", "tests.test_app", "test_all"),
]


def run_all():
    print("=" * 75)
    print("      BugFlow Automated Test Suite Runner (Milestone 3 Module 6)")
    print("=" * 75)
    print(f"Working Directory: {WORKSPACE_ROOT}")
    print(f"Python Executable: {sys.executable}")
    print(f"Total In-Process Suites: {len(SUITES)}\n")

    results = []
    start_total = time.time()

    for idx, (name, mod_name, func_name) in enumerate(SUITES, 1):
        print(f"[{idx}/{len(SUITES)}] Running {name} ({mod_name}.py)...")
        suite_start = time.time()
        try:
            mod = importlib.import_module(mod_name)
            func = getattr(mod, func_name)
            func()
            elapsed = time.time() - suite_start
            print(f"--> [SUCCESS] {name} completed in {elapsed:.2f}s\n")
            results.append((name, "PASSED", elapsed, None))
        except Exception as e:
            elapsed = time.time() - suite_start
            print(f"--> [FAILED] {name} failed in {elapsed:.2f}s: {e}\n")
            traceback.print_exc()
            results.append((name, "FAILED", elapsed, str(e) or e.__class__.__name__))

    total_elapsed = time.time() - start_total

    print("=" * 75)
    print("                      TEST EXECUTION SUMMARY")
    print("=" * 75)
    passed_count = sum(1 for _, status, _, _ in results if status == "PASSED")
    failed_count = sum(1 for _, status, _, _ in results if status == "FAILED")

    for name, status, elapsed, err in results:
        status_display = f"[{status}]"
        print(f"  {status_display:<10} {name:<52} ({elapsed:.2f}s)")
        if err:
            print(f"             Error: {err}")

    print("-" * 75)
    print(f"Total Suites: {len(SUITES)} | Passed: {passed_count} | Failed: {failed_count} | Duration: {total_elapsed:.2f}s")
    print("=" * 75)

    if failed_count > 0:
        print("\nCI/CD Check FAILED. One or more test suites failed.")
        sys.exit(1)
    else:
        print("\nCI/CD Check PASSED. All test suites passed successfully.")
        sys.exit(0)


if __name__ == "__main__":
    run_all()

