import datetime
import functools
import hashlib
import hmac
import os
import re
import secrets
import sys

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
# ponytail: simple session secret fallback for development
app.secret_key = os.getenv("SECRET_KEY", "bugflow-secret-session-key-dev-2026")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# File upload configuration for Milestone 2
UPLOAD_FOLDER = os.path.join(app.instance_path, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt"}
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

DATABASE_URL = os.getenv("DATABASE_URL")

# Milestone 2: Issue Classifications & Categories
NEW_ISSUE_TYPES = ["Bug", "Feature Request", "Enhancement", "Technical Debt"]
ALL_ISSUE_TYPES = ["Bug", "Feature Request", "Enhancement", "Technical Debt", "Support Ticket"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
NEW_PRIORITIES = ["P1", "P2", "P3", "P4"]
ALL_PRIORITIES = ["P0", "P1", "P2", "P3", "P4"]
ROLES = ["ADMIN", "PROJECT_MANAGER", "DEVELOPER", "TESTER"]

PRIORITY_MEANINGS = {
    "P1": "P1 — Fix immediately",
    "P2": "P2 — Fix soon",
    "P3": "P3 — Fix when possible",
    "P4": "P4 — Low-priority fix",
    "P0": "P0 — Blocker (Legacy)",
}

# Module 4: Sequential 5-stage lifecycle transitions
WORKFLOW_SEQUENCE = ["Open", "In Progress", "Testing", "Resolved", "Closed"]
WORKFLOW_TRANSITIONS = {
    "Open": ["In Progress"],
    "In Progress": ["Testing"],
    "Testing": ["Resolved"],
    "Resolved": ["Closed"],
    "Closed": [],
}


def allowed_file(filename):
    """Validates permitted file extensions for attachments."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def log_activity(cur, issue_id, user_id, action_type, description, old_value=None, new_value=None):
    """Inserts a structured audit entry into activity_history."""
    cur.execute("""
        INSERT INTO activity_history (
            issue_id, user_id, action_type, description, old_value, new_value, created_at
        ) VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
    """, (issue_id, user_id, action_type, description, old_value, new_value))


def generate_sprint_id(cur, project_id):
    """Generates the next sequential sprint ID for a project (e.g. SP-01-07)."""
    proj_num = int(project_id.replace("PRJ-", ""))
    prefix = f"SP-{proj_num:02d}"
    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("sprints_sprint_id",))
    cur.execute(
        "SELECT COALESCE(MAX(SUBSTRING(sprint_id FROM %s)::INTEGER), 0) + 1 AS next_num "
        "FROM sprints WHERE sprint_id LIKE %s",
        (r"(\d+)$", f"{prefix}-%")
    )
    next_num = cur.fetchone()["next_num"]
    return f"{prefix}-{next_num:02d}"


# ---------------------------------------------------------------------------
# Database connection helpers
# ---------------------------------------------------------------------------
_RESOLVED_HOSTADDR = None


def get_db():
    """Returns a per-request psycopg database connection."""
    global _RESOLVED_HOSTADDR
    if "db" not in g:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL is not set in environment.")
        try:
            if _RESOLVED_HOSTADDR:
                g.db = psycopg.connect(DATABASE_URL, hostaddr=_RESOLVED_HOSTADDR, row_factory=dict_row)
            else:
                g.db = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        except psycopg.OperationalError as e:
            if "getaddrinfo failed" in str(e):
                import subprocess
                import urllib.parse
                u = urllib.parse.urlparse(DATABASE_URL)
                res = subprocess.check_output(
                    ["powershell", "-Command", f"(Resolve-DnsName {u.hostname} -Server 8.8.8.8 -Type A).IP4Address"],
                    text=True
                ).strip().split()
                if res:
                    _RESOLVED_HOSTADDR = res[0]
                    g.db = psycopg.connect(DATABASE_URL, hostaddr=_RESOLVED_HOSTADDR, row_factory=dict_row)
                else:
                    raise
            else:
                raise
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """Closes the per-request database connection."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def get_next_id(cur, table, column, prefix, padding=3):
    """Generates the next sequential ID with prefix and zero-padding directly in PostgreSQL.
    Uses transaction advisory lock to guarantee concurrency safety and avoid duplicate IDs."""
    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"{table}_{column}",))
    query = sql.SQL(
        "SELECT COALESCE(MAX(SUBSTRING({col} FROM %s)::INTEGER), 0) + 1 AS next_num "
        "FROM {tbl} WHERE {col} LIKE %s"
    ).format(col=sql.Identifier(column), tbl=sql.Identifier(table))
    cur.execute(query, (r"(\d+)", f"{prefix}-%"))
    next_num = cur.fetchone()["next_num"]
    return f"{prefix}-{next_num:0{padding}d}"


# ---------------------------------------------------------------------------
# Security & CSRF
# ---------------------------------------------------------------------------
@app.before_request
def csrf_protect():
    """Simple session-based CSRF protection for all state-changing POST requests."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    # API endpoints and GitHub webhooks bypass browser form-based redirect CSRF
    if request.path.startswith("/api/") or request.path == "/webhooks/github":
        return

    if request.method == "POST":
        token = request.form.get("csrf_token")
        if not token or token != session.get("csrf_token"):
            flash("Security check failed: invalid or expired session token. Please try again.", "danger")
            return redirect(request.referrer or url_for("dashboard"))


@app.errorhandler(413)
def request_entity_too_large(error):
    flash("File exceeds the maximum upload limit of 5 MB.", "danger")
    return redirect(request.referrer or url_for("issues_list"))


@app.context_processor
def inject_globals():
    """Injects CSRF token, current date, and permission helpers into all templates."""
    today = datetime.date.today().strftime("%b %d, %Y")
    
    def can_edit(issue):
        role = session.get("role")
        user_id = session.get("user_id")
        if not role:
            return False
        if role == "ADMIN":
            return True
        if role == "PROJECT_MANAGER":
            # PMs can edit issues in projects they manage
            return issue.get("project_manager_id") == user_id or issue.get("project_id") in session.get("pm_project_ids", [])
        if role == "DEVELOPER":
            return issue.get("assigned_to") == user_id
        if role == "TESTER":
            return issue.get("created_by") == user_id
        return False

    def can_delete(issue):
        role = session.get("role")
        user_id = session.get("user_id")
        if not role:
            return False
        if role == "ADMIN":
            return True
        if role == "PROJECT_MANAGER":
            return issue.get("project_manager_id") == user_id or issue.get("project_id") in session.get("pm_project_ids", [])
        return False

    def can_update_status(issue):
        role = session.get("role")
        user_id = session.get("user_id")
        if not role:
            return False
        if role in ["ADMIN", "PROJECT_MANAGER"]:
            return True
        if role == "DEVELOPER" and issue.get("assigned_to") == user_id:
            return True
        if role == "TESTER":
            return True
        return False

    return dict(
        csrf_token=session.get("csrf_token"),
        today_date=today,
        can_edit=can_edit,
        can_delete=can_delete,
        can_update_status=can_update_status,
        issue_types=NEW_ISSUE_TYPES,
        all_issue_types=ALL_ISSUE_TYPES,
        severities=SEVERITIES,
        priorities=NEW_PRIORITIES,
        all_priorities=ALL_PRIORITIES,
        priority_meanings=PRIORITY_MEANINGS,
        workflow_sequence=WORKFLOW_SEQUENCE,
        workflow_transitions=WORKFLOW_TRANSITIONS,
        roles_list=ROLES,
    )


# ---------------------------------------------------------------------------
# Authorization Decorators
# ---------------------------------------------------------------------------
def login_required(view):
    """Enforces authentication for protected routes."""
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped_view


def roles_required(*allowed_roles):
    """Enforces role-based server-side authorization."""
    def decorator(view):
        @functools.wraps(view)
        def wrapped_view(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            user_role = session.get("role")
            if user_role not in allowed_roles:
                flash("Access denied: your account role does not have permission for this section.", "danger")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped_view
    return decorator


# ---------------------------------------------------------------------------
# Authentication Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter both email and password.", "danger")
            return render_template("auth/login.html", email=email)

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT user_id, display_name, email, role, active, password_hash 
                FROM users 
                WHERE LOWER(email) = %s
            """, (email,))
            user = cur.fetchone()

        if not user:
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", email=email)

        if not user["active"]:
            flash("This account has been deactivated. Please contact an administrator.", "danger")
            return render_template("auth/login.html", email=email)

        if not user["password_hash"]:
            flash("Password not yet configured for this imported account. Please run 'python setup_admin.py' or ask an administrator.", "warning")
            return render_template("auth/login.html", email=email)

        if not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", email=email)

        # Successful login: populate session
        session.clear()
        session["csrf_token"] = secrets.token_hex(16)
        session["user_id"] = user["user_id"]
        session["display_name"] = user["display_name"]
        session["email"] = user["email"]
        session["role"] = user["role"]

        # Cache PM managed project IDs for quick permission checks
        if user["role"] == "PROJECT_MANAGER":
            with conn.cursor() as cur:
                cur.execute("SELECT project_id FROM projects WHERE project_manager_id = %s", (user["user_id"],))
                session["pm_project_ids"] = [row["project_id"] for row in cur.fetchall()]

        flash(f"Welcome back, {user['display_name']}!", "success")
        next_url = request.args.get("next")
        if next_url and next_url.startswith("/"):
            return redirect(next_url)
        return redirect(url_for("dashboard"))

    return render_template("auth/login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not display_name or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("auth/register.html", display_name=display_name, email=email)

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template("auth/register.html", display_name=display_name, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html", display_name=display_name, email=email)

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM users WHERE LOWER(email) = %s", (email,))
            if cur.fetchone():
                flash("An account with this email address already exists.", "danger")
                return render_template("auth/register.html", display_name=display_name, email=email)

            next_user_id = get_next_id(cur, "users", "user_id", "USR", 3)

            # Always DEVELOPER role for self-registration
            role = "DEVELOPER"
            password_hash = generate_password_hash(password)

            cur.execute("""
                INSERT INTO users (user_id, display_name, email, role, active, password_hash)
                VALUES (%s, %s, %s, %s, TRUE, %s)
            """, (next_user_id, display_name, email, role, password_hash))
            conn.commit()

        flash("Account created successfully! Please sign in with your credentials.", "success")
        return redirect(url_for("login"))

    return render_template("auth/register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Dashboard Route (Role Scoped & Milestone 3 Analytics Visualizations)
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    role = session.get("role")
    user_id = session.get("user_id")
    project_id = request.args.get("project_id")
    if project_id:
        project_id = str(project_id).strip()

    with conn.cursor() as cur:
        # Validate project_id if provided
        selected_project = None
        if project_id:
            cur.execute("SELECT project_id, project_name, project_manager_id FROM projects WHERE project_id = %s", (project_id,))
            selected_project = cur.fetchone()
            if not selected_project:
                abort(404)
            if role == "PROJECT_MANAGER" and selected_project["project_manager_id"] != user_id:
                abort(403)

        # Accessible projects for the project filter dropdown
        if role == "PROJECT_MANAGER":
            cur.execute("SELECT project_id, project_name FROM projects WHERE project_manager_id = %s ORDER BY project_id", (user_id,))
            accessible_projects = cur.fetchall()
        else:
            cur.execute("SELECT project_id, project_name FROM projects ORDER BY project_id")
            accessible_projects = cur.fetchall()

        # Scope filter for issues
        if project_id:
            role_scope_msg = f"Project: {selected_project['project_name']} ({project_id})"
            scope_filter = "WHERE i.project_id = %s"
            params = [project_id]
        elif role == "PROJECT_MANAGER":
            role_scope_msg = "Managed Projects view"
            scope_filter = "WHERE i.project_id IN (SELECT project_id FROM projects WHERE project_manager_id = %s)"
            params = [user_id]
        elif role == "DEVELOPER":
            role_scope_msg = "Assigned Issues view"
            scope_filter = "WHERE i.assigned_to = %s"
            params = [user_id]
        elif role == "TESTER":
            role_scope_msg = "Quality & Verification view"
            scope_filter = "WHERE (i.created_by = %s OR i.status = 'Testing')"
            params = [user_id]
        else:
            role_scope_msg = "System-wide view"
            scope_filter = ""
            params = []

        # 1. Summary & Status & Severity counts
        cur.execute(f"""
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
                COUNT(*) FILTER (WHERE severity = 'Low') AS low_issues,
                COUNT(*) FILTER (WHERE assigned_to IS NULL) AS unassigned_issues
            FROM issues i
            {scope_filter};
        """, params)
        counts = cur.fetchone()

        total = counts["total_issues"] or 0
        resolved_cnt = counts["resolved_issues"] or 0
        closed_cnt = counts["closed_issues"] or 0
        resolved_closed = resolved_cnt + closed_cnt
        res_pct = round((resolved_closed * 100.0) / total, 2) if total > 0 else 0.0

        # 2. Average Resolution Time
        cur.execute(f"""
            SELECT 
                COUNT(*) AS sample_size,
                ROUND(AVG(res.effective_hours), 2) AS avg_hours,
                ROUND(AVG(res.effective_hours) / 24.0, 2) AS avg_days
            FROM issues i
            JOIN (
                SELECT 
                    i_inner.issue_id,
                    COALESCE(
                        i_inner.resolution_time_hours,
                        EXTRACT(EPOCH FROM (h.created_at - i_inner.created_date::timestamp)) / 3600.0,
                        CASE WHEN i_inner.resolved_date IS NOT NULL AND i_inner.resolved_date >= i_inner.created_date 
                             THEN (i_inner.resolved_date - i_inner.created_date) * 24.0 ELSE NULL END
                    ) AS effective_hours
                FROM issues i_inner
                LEFT JOIN (
                    SELECT issue_id, MIN(created_at) AS created_at
                    FROM activity_history
                    WHERE new_value = 'Resolved'
                    GROUP BY issue_id
                ) h ON i_inner.issue_id = h.issue_id
                WHERE i_inner.status IN ('Resolved', 'Closed')
            ) res ON i.issue_id = res.issue_id
            {scope_filter}
            {'AND' if scope_filter else 'WHERE'} res.effective_hours IS NOT NULL AND res.effective_hours >= 0;
        """, params)
        time_row = cur.fetchone()
        avg_res_hours = float(time_row["avg_hours"]) if time_row and time_row["avg_hours"] is not None else 0.0
        avg_res_days = float(time_row["avg_days"]) if time_row and time_row["avg_days"] is not None else 0.0

        # 3. Monthly Trends
        cur.execute(f"""
            SELECT TO_CHAR(DATE_TRUNC('month', created_date), 'YYYY-MM') AS month, COUNT(*) AS reported_count
            FROM issues i
            {scope_filter}
            {'AND' if scope_filter else 'WHERE'} created_date IS NOT NULL
            GROUP BY 1
            ORDER BY 1;
        """, params)
        reported_rows = cur.fetchall()

        cur.execute(f"""
            SELECT TO_CHAR(DATE_TRUNC('month', COALESCE(h.created_at::date, i.resolved_date, i.updated_date)), 'YYYY-MM') AS month, COUNT(*) AS resolved_count
            FROM issues i
            LEFT JOIN (
                SELECT issue_id, MIN(created_at) AS created_at
                FROM activity_history
                WHERE new_value = 'Resolved'
                GROUP BY issue_id
            ) h ON i.issue_id = h.issue_id
            {scope_filter}
            {'AND' if scope_filter else 'WHERE'} i.status IN ('Resolved', 'Closed')
              AND COALESCE(h.created_at::date, i.resolved_date, i.updated_date) IS NOT NULL
            GROUP BY 1
            ORDER BY 1;
        """, params)
        resolved_rows = cur.fetchall()

        rep_map = {r["month"]: r["reported_count"] for r in reported_rows if r["month"]}
        res_map = {r["month"]: r["resolved_count"] for r in resolved_rows if r["month"]}
        all_months = sorted(set(list(rep_map.keys()) + list(res_map.keys())))
        trends_data = [
            {"month": m, "reported_count": rep_map.get(m, 0), "resolved_count": res_map.get(m, 0)}
            for m in all_months
        ]

        # 4. Module breakdown
        cur.execute(f"""
            SELECT 
                COALESCE(NULLIF(TRIM(component), ''), 'Unassigned') AS module_name,
                COUNT(*) AS total_defects,
                COUNT(*) FILTER (WHERE status = 'Open') AS open_defects,
                COUNT(*) FILTER (WHERE status = 'In Progress') AS in_progress_defects,
                COUNT(*) FILTER (WHERE status = 'Testing') AS testing_defects,
                COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved_defects,
                COUNT(*) FILTER (WHERE status = 'Closed') AS closed_defects,
                COUNT(*) FILTER (WHERE status NOT IN ('Resolved', 'Closed')) AS pending_defects,
                COUNT(*) FILTER (WHERE severity = 'Critical') AS critical_count,
                COUNT(*) FILTER (WHERE severity = 'High') AS high_count,
                COUNT(*) FILTER (WHERE severity = 'Medium') AS medium_count,
                COUNT(*) FILTER (WHERE severity = 'Low') AS low_count
            FROM issues i
            {scope_filter}
            GROUP BY 1
            ORDER BY total_defects DESC, module_name;
        """, params)
        modules_data = cur.fetchall()

        # 5. Project-wise statistics (when in system-wide or multi-project view)
        if not project_id and role in ["ADMIN", "PROJECT_MANAGER", "DEVELOPER", "TESTER"]:
            if role == "PROJECT_MANAGER":
                p_where = "WHERE p.project_manager_id = %s"
                p_params = [user_id]
            else:
                p_where = ""
                p_params = []
            cur.execute(f"""
                SELECT 
                    p.project_id,
                    p.project_name,
                    p.project_manager_id,
                    p.lifecycle_status,
                    COUNT(i.issue_id) AS total_issues,
                    COUNT(i.issue_id) FILTER (WHERE i.status = 'Open') AS open_issues,
                    COUNT(i.issue_id) FILTER (WHERE i.status = 'In Progress') AS in_progress_issues,
                    COUNT(i.issue_id) FILTER (WHERE i.status = 'Testing') AS testing_issues,
                    COUNT(i.issue_id) FILTER (WHERE i.status = 'Resolved') AS resolved_issues,
                    COUNT(i.issue_id) FILTER (WHERE i.status = 'Closed') AS closed_issues,
                    COUNT(i.issue_id) FILTER (WHERE i.status NOT IN ('Resolved', 'Closed')) AS pending_issues,
                    CASE WHEN COUNT(i.issue_id) > 0 
                         THEN ROUND((COUNT(i.issue_id) FILTER (WHERE i.status IN ('Resolved', 'Closed')) * 100.0) / COUNT(i.issue_id), 2)
                         ELSE 0.00 END AS resolution_percentage,
                    ROUND(AVG(res.effective_hours), 2) AS avg_resolution_hours
                FROM projects p
                LEFT JOIN issues i ON p.project_id = i.project_id
                LEFT JOIN (
                    SELECT 
                        i_inner.issue_id,
                        COALESCE(
                            i_inner.resolution_time_hours,
                            EXTRACT(EPOCH FROM (h.created_at - i_inner.created_date::timestamp)) / 3600.0,
                            CASE WHEN i_inner.resolved_date IS NOT NULL AND i_inner.resolved_date >= i_inner.created_date 
                                 THEN (i_inner.resolved_date - i_inner.created_date) * 24.0 ELSE NULL END
                        ) AS effective_hours
                    FROM issues i_inner
                    LEFT JOIN (
                        SELECT issue_id, MIN(created_at) AS created_at
                        FROM activity_history
                        WHERE new_value = 'Resolved'
                        GROUP BY issue_id
                    ) h ON i_inner.issue_id = h.issue_id
                    WHERE i_inner.status IN ('Resolved', 'Closed')
                ) res ON i.issue_id = res.issue_id AND res.effective_hours >= 0
                {p_where}
                GROUP BY p.project_id, p.project_name, p.project_manager_id, p.lifecycle_status
                ORDER BY p.project_id;
            """, p_params)
            project_stats = cur.fetchall()
        else:
            project_stats = []

        # 6. Recent 6 issues (preserving Milestone 1 functionality)
        cur.execute(f"""
            SELECT i.issue_id, i.title, i.issue_type, i.priority, i.status, i.created_date
            FROM issues i
            {scope_filter}
            ORDER BY i.created_date DESC, i.issue_id DESC
            LIMIT 6
        """, params)
        recent_issues = cur.fetchall()

    kpis = {
        "total": total,
        "open": counts["open_issues"] or 0,
        "in_progress": counts["in_progress_issues"] or 0,
        "testing": counts["testing_issues"] or 0,
        "resolved": resolved_cnt,
        "closed": closed_cnt,
        "pending": counts["pending_issues"] or 0,
        "resolution_percentage": res_pct,
        "avg_resolution_hours": avg_res_hours,
        "avg_resolution_days": avg_res_days,
        "critical": counts["critical_issues"] or 0,
        "high": counts["high_issues"] or 0,
        "medium": counts["medium_issues"] or 0,
        "low": counts["low_issues"] or 0,
        "unassigned": counts["unassigned_issues"] or 0,
        "resolved_all": resolved_closed,
    }

    defect_density = {
        "available": False,
        "reason": "Code-size denominator (KLOC/LOC) not present in database schema."
    }

    today_date = datetime.date.today().strftime("%b %d, %Y")

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        kpis=kpis,
        stats=kpis,  # Backwards compatibility
        selected_project_id=project_id or "",
        accessible_projects=accessible_projects,
        role_scope_msg=role_scope_msg,
        trends_data=trends_data,
        modules_data=modules_data,
        project_stats=project_stats,
        recent_issues=recent_issues,
        defect_density=defect_density,
        today_date=today_date,
    )


# ---------------------------------------------------------------------------
# Issue Management Routes
# ---------------------------------------------------------------------------
@app.route("/issues")
@login_required
def issues_list():
    conn = get_db()
    role = session.get("role")
    user_id = session.get("user_id")

    # Read filter query parameters
    q = request.args.get("q", "").strip()
    project_id = request.args.get("project_id", "").strip()
    issue_type = request.args.get("issue_type", "").strip()
    status = request.args.get("status", "").strip()
    priority = request.args.get("priority", "").strip()
    severity = request.args.get("severity", "").strip()
    module = request.args.get("module", "").strip()
    page = max(1, int(request.args.get("page", 1)))
    per_page = 15

    conditions = []
    params = []

    # Developer defaults to their assigned issues unless explicitly searching all
    if role == "DEVELOPER" and not request.args.get("all"):
        conditions.append("i.assigned_to = %s")
        params.append(user_id)

    if q:
        conditions.append("(i.issue_id ILIKE %s OR i.title ILIKE %s OR i.component ILIKE %s)")
        search_pattern = f"%{q}%"
        params.extend([search_pattern, search_pattern, search_pattern])

    if project_id:
        conditions.append("i.project_id = %s")
        params.append(project_id)

    if issue_type:
        conditions.append("i.issue_type = %s")
        params.append(issue_type)

    if status:
        conditions.append("i.status = %s")
        params.append(status)

    if priority:
        conditions.append("i.priority = %s")
        params.append(priority)

    if severity:
        conditions.append("i.severity = %s")
        params.append(severity)

    if module:
        conditions.append("i.component = %s")
        params.append(module)

    where_sql = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with conn.cursor() as cur:
        # Total matching records count
        count_sql = f"SELECT COUNT(*) AS total FROM issues i {where_sql}"
        cur.execute(count_sql, params)
        total_count = cur.fetchone()["total"]

        total_pages = max(1, (total_count + per_page - 1) // per_page)
        offset = (page - 1) * per_page

        # Fetch page records including component and created_date
        query_sql = f"""
            SELECT 
                i.issue_id, i.title, i.issue_type, i.priority, i.severity, i.status,
                i.component, i.created_date,
                i.project_id, p.project_name, p.project_manager_id,
                i.assigned_to, u_assign.display_name AS assignee_name,
                i.created_by, u_creator.display_name AS creator_name
            FROM issues i
            JOIN projects p ON i.project_id = p.project_id
            LEFT JOIN users u_assign ON i.assigned_to = u_assign.user_id
            JOIN users u_creator ON i.created_by = u_creator.user_id
            {where_sql}
            ORDER BY i.issue_id DESC
            LIMIT %s OFFSET %s
        """
        cur.execute(query_sql, params + [per_page, offset])
        issues = cur.fetchall()

        # Fetch filter dropdown options
        cur.execute("SELECT project_id, project_name FROM projects ORDER BY project_name")
        projects = cur.fetchall()

        cur.execute("SELECT state_name FROM workflow_states ORDER BY sequence")
        workflow_states = [row["state_name"] for row in cur.fetchall()]

        # Fetch distinct affected modules
        cur.execute("SELECT DISTINCT component FROM issues WHERE component IS NOT NULL AND component != '' ORDER BY component")
        modules = [row["component"] for row in cur.fetchall()]

        # Quick summary stats
        cur.execute("""
            SELECT 
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'Open') AS open_count,
                COUNT(*) FILTER (WHERE status IN ('In Progress', 'Testing')) AS in_progress_count,
                COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved_count,
                COUNT(*) FILTER (WHERE status = 'Closed') AS closed_count
            FROM issues
        """)
        stats = cur.fetchone()

    # Helper for building pagination URLs with existing filters
    def page_url(p_num):
        args = request.args.to_dict()
        args["page"] = p_num
        return url_for("issues_list", **args)

    start_index = offset + 1 if total_count > 0 else 0
    end_index = min(offset + per_page, total_count)
    page_range = range(max(1, page - 2), min(total_pages + 1, page + 3))

    return render_template(
        "issues/list.html",
        active_page="issues",
        issues=issues,
        projects=projects,
        workflow_states=workflow_states,
        modules=modules,
        stats=stats,
        filters=dict(q=q, project_id=project_id, issue_type=issue_type, status=status, priority=priority, severity=severity, module=module),
        total_count=total_count,
        total_pages=total_pages,
        current_page=page,
        start_index=start_index,
        end_index=end_index,
        page_range=page_range,
        page_url=page_url,
    )


@app.route("/issues/create", methods=["GET", "POST"])
@login_required
def issue_create():
    role = session.get("role")
    if role not in ["ADMIN", "PROJECT_MANAGER", "TESTER"]:
        flash("Only administrators, project managers, and testers can create new issues.", "danger")
        return redirect(url_for("issues_list"))

    conn = get_db()

    if request.method == "POST":
        project_id = request.form.get("project_id", "").strip()
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        issue_type = request.form.get("issue_type", "Bug").strip()
        severity = request.form.get("severity", "Medium").strip()
        priority = request.form.get("priority", "P2").strip()
        status = "Open"  # New issues always start at Open in the lifecycle
        assigned_to = request.form.get("assigned_to", "").strip() or None
        sprint_id = request.form.get("sprint_id", "").strip() or None
        component = request.form.get("component", "").strip() or None
        environment = request.form.get("environment", "").strip() or None
        steps_to_reproduce = request.form.get("steps_to_reproduce", "").strip() or None
        expected_result = request.form.get("expected_result", "").strip() or None
        actual_result = request.form.get("actual_result", "").strip() or None
        business_impact = request.form.get("business_impact", "").strip() or None

        if not project_id or not title or not description:
            flash("Project, Title, and Description are required.", "danger")
            form_data = request.form
        elif issue_type not in NEW_ISSUE_TYPES:
            flash(f"Invalid issue type. Must be one of: {', '.join(NEW_ISSUE_TYPES)}", "danger")
            form_data = request.form
        elif severity not in SEVERITIES:
            flash(f"Invalid severity. Must be one of: {', '.join(SEVERITIES)}", "danger")
            form_data = request.form
        elif priority not in NEW_PRIORITIES:
            flash(f"Invalid priority. Must be one of: {', '.join(NEW_PRIORITIES)}", "danger")
            form_data = request.form
        else:
            with conn.cursor() as cur:
                next_issue_id = get_next_id(cur, "issues", "issue_id", "BUG", 5)
                created_date = datetime.date.today()

                cur.execute("""
                    INSERT INTO issues (
                        issue_id, title, description, issue_type, severity, priority,
                        status, project_id, assigned_to, created_by, created_date,
                        updated_date, component, environment, steps_to_reproduce,
                        expected_result, actual_result, business_impact, sprint_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s
                    )
                """, (
                    next_issue_id, title, description, issue_type, severity, priority,
                    status, project_id, assigned_to, session["user_id"], created_date,
                    created_date, component, environment, steps_to_reproduce,
                    expected_result, actual_result, business_impact, sprint_id
                ))

                # Record creation in activity history
                log_activity(cur, next_issue_id, session["user_id"], "CREATED", "Issue created")

                if assigned_to:
                    cur.execute("SELECT display_name FROM users WHERE user_id = %s", (assigned_to,))
                    u_assign = cur.fetchone()
                    assignee_name = u_assign["display_name"] if u_assign else assigned_to
                    log_activity(cur, next_issue_id, session["user_id"], "ASSIGNED", f"Assigned to {assignee_name}", new_value=assignee_name)

                # Optional initial attachment during creation
                if "attachment" in request.files:
                    file = request.files["attachment"]
                    if file and file.filename and allowed_file(file.filename):
                        file_bytes = file.read()
                        if len(file_bytes) <= MAX_UPLOAD_SIZE:
                            safe_name = secure_filename(file.filename) or "attachment"
                            ext = safe_name.rsplit(".", 1)[1].lower() if "." in safe_name else "bin"
                            stored_name = f"{secrets.token_hex(8)}_{int(datetime.datetime.now().timestamp())}.{ext}"
                            target_path = os.path.abspath(os.path.join(app.config["UPLOAD_FOLDER"], stored_name))
                            if target_path.startswith(os.path.abspath(app.config["UPLOAD_FOLDER"])):
                                with open(target_path, "wb") as f:
                                    f.write(file_bytes)
                                cur.execute("""
                                    INSERT INTO attachments (
                                        issue_id, user_id, original_filename, stored_filename, file_size, content_type, created_at
                                    ) VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                                """, (next_issue_id, session["user_id"], file.filename, stored_name, len(file_bytes), file.mimetype or "application/octet-stream"))
                                log_activity(cur, next_issue_id, session["user_id"], "ATTACHMENT_ADDED", f"Attachment added: {file.filename}")

                conn.commit()

            flash(f"Issue {next_issue_id} created successfully!", "success")
            return redirect(url_for("issue_detail", issue_id=next_issue_id))
    else:
        form_data = {"project_id": request.args.get("project_id", "")}

    with conn.cursor() as cur:
        cur.execute("SELECT project_id, project_name FROM projects ORDER BY project_name")
        projects = cur.fetchall()

        cur.execute("SELECT user_id, display_name, role FROM users WHERE active = TRUE ORDER BY display_name")
        users = cur.fetchall()

        cur.execute("SELECT state_name FROM workflow_states ORDER BY sequence")
        workflow_states = [row["state_name"] for row in cur.fetchall()]

        cur.execute("""
            SELECT s.sprint_id, s.sprint_name, s.status, p.project_name 
            FROM sprints s 
            JOIN projects p ON s.project_id = p.project_id 
            ORDER BY s.sprint_id
        """)
        sprints = cur.fetchall()

    return render_template(
        "issues/create.html",
        active_page="issues",
        form_data=form_data,
        projects=projects,
        users=users,
        workflow_states=workflow_states,
        sprints=sprints,
    )


@app.route("/issues/<issue_id>")
@login_required
def issue_detail(issue_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT 
                i.*, 
                p.project_name, p.project_manager_id,
                u_assign.display_name AS assignee_name,
                u_creator.display_name AS creator_name,
                s.sprint_name
            FROM issues i
            JOIN projects p ON i.project_id = p.project_id
            LEFT JOIN users u_assign ON i.assigned_to = u_assign.user_id
            JOIN users u_creator ON i.created_by = u_creator.user_id
            LEFT JOIN sprints s ON i.sprint_id = s.sprint_id
            WHERE i.issue_id = %s
        """, (issue_id,))
        issue = cur.fetchone()

        if not issue:
            flash(f"Issue {issue_id} not found.", "danger")
            return redirect(url_for("issues_list"))

        # Fetch comments for this issue
        cur.execute("""
            SELECT c.*, u.display_name AS author_name, u.role AS author_role
            FROM comments c
            JOIN users u ON c.user_id = u.user_id
            WHERE c.issue_id = %s
            ORDER BY c.created_at ASC
        """, (issue_id,))
        comments = cur.fetchall()

        # Fetch attachments for this issue
        cur.execute("""
            SELECT a.*, u.display_name AS uploader_name
            FROM attachments a
            JOIN users u ON a.user_id = u.user_id
            WHERE a.issue_id = %s
            ORDER BY a.created_at DESC
        """, (issue_id,))
        attachments = cur.fetchall()

        # Fetch activity history for this issue
        cur.execute("""
            SELECT h.*, u.display_name AS actor_name
            FROM activity_history h
            JOIN users u ON h.user_id = u.user_id
            WHERE h.issue_id = %s
            ORDER BY h.created_at DESC
        """, (issue_id,))
        activity_history = cur.fetchall()

        # Fetch linked GitHub commits for this issue (Milestone 3 Module 2)
        cur.execute("""
            SELECT commit_id, commit_sha, issue_id, commit_message, commit_author,
                   repository_name, repository_url, committed_at, created_at
            FROM commits
            WHERE issue_id = %s
            ORDER BY committed_at DESC
        """, (issue_id,))
        commits = cur.fetchall()

        cur.execute("SELECT state_name FROM workflow_states ORDER BY sequence")
        workflow_states = [row["state_name"] for row in cur.fetchall()]

    allowed_transitions = WORKFLOW_TRANSITIONS.get(issue["status"], [])

    return render_template(
        "issues/detail.html",
        active_page="issues",
        issue=issue,
        workflow_states=workflow_states,
        comments=comments,
        attachments=attachments,
        activity_history=activity_history,
        commits=commits,
        allowed_transitions=allowed_transitions,
    )


@app.route("/issues/<issue_id>/edit", methods=["GET", "POST"])
@login_required
def issue_edit(issue_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT i.*, p.project_manager_id 
            FROM issues i 
            JOIN projects p ON i.project_id = p.project_id 
            WHERE i.issue_id = %s
        """, (issue_id,))
        issue = cur.fetchone()

    if not issue:
        flash(f"Issue {issue_id} not found.", "danger")
        return redirect(url_for("issues_list"))

    # Permission check
    role = session.get("role")
    user_id = session.get("user_id")
    authorized = (
        role == "ADMIN" or
        (role == "PROJECT_MANAGER" and issue["project_manager_id"] == user_id) or
        (role == "DEVELOPER" and issue["assigned_to"] == user_id) or
        (role == "TESTER" and issue["created_by"] == user_id)
    )
    if not authorized:
        flash("You are not authorized to edit this issue.", "danger")
        return redirect(url_for("issue_detail", issue_id=issue_id))

    if request.method == "POST":
        project_id = request.form.get("project_id", issue["project_id"])
        title = request.form.get("title", issue["title"]).strip()
        description = request.form.get("description", issue["description"]).strip()
        issue_type = request.form.get("issue_type", issue["issue_type"]).strip()
        severity = request.form.get("severity", issue["severity"]).strip()
        priority = request.form.get("priority", issue["priority"]).strip()
        status = request.form.get("status", issue["status"]).strip()
        assigned_to = request.form.get("assigned_to", "").strip() or None
        sprint_id = request.form.get("sprint_id", "").strip() or None
        component = request.form.get("component", "").strip() or None
        environment = request.form.get("environment", "").strip() or None
        steps_to_reproduce = request.form.get("steps_to_reproduce", "").strip() or None
        expected_result = request.form.get("expected_result", "").strip() or None
        actual_result = request.form.get("actual_result", "").strip() or None
        resolution_summary = request.form.get("resolution_summary", "").strip() or None
        root_cause = request.form.get("root_cause", "").strip() or None
        updated_date = datetime.date.today()

        # Validate types, severity, priority
        if issue_type not in ALL_ISSUE_TYPES:
            flash("Invalid issue type selected.", "danger")
            return redirect(url_for("issue_edit", issue_id=issue_id))
        if severity not in SEVERITIES:
            flash("Invalid severity selected.", "danger")
            return redirect(url_for("issue_edit", issue_id=issue_id))
        if priority not in ALL_PRIORITIES:
            flash("Invalid priority selected.", "danger")
            return redirect(url_for("issue_edit", issue_id=issue_id))

        with conn.cursor() as cur:
            # Check lifecycle status transition if status was altered
            if status != issue["status"]:
                allowed = WORKFLOW_TRANSITIONS.get(issue["status"], [])
                if status not in allowed:
                    flash(
                        f"Invalid workflow transition: Cannot move from '{issue['status']}' to '{status}'. "
                        f"Permitted next status: {', '.join(allowed) or 'None (terminal)'}.",
                        "danger"
                    )
                    return redirect(url_for("issue_edit", issue_id=issue_id))

                log_activity(
                    cur, issue_id, user_id, "STATUS_CHANGED",
                    f"Status changed from {issue['status']} to {status}",
                    old_value=issue["status"], new_value=status
                )

            # Check assignment change
            if assigned_to != issue["assigned_to"]:
                new_name = "Unassigned"
                if assigned_to:
                    cur.execute("SELECT display_name FROM users WHERE user_id = %s", (assigned_to,))
                    u = cur.fetchone()
                    if u:
                        new_name = u["display_name"]
                log_activity(cur, issue_id, user_id, "ASSIGNED", f"Assigned to {new_name}", new_value=new_name)

            # Check sprint change
            if sprint_id != issue["sprint_id"]:
                if sprint_id:
                    cur.execute("SELECT sprint_name FROM sprints WHERE sprint_id = %s", (sprint_id,))
                    s = cur.fetchone()
                    s_name = s["sprint_name"] if s else sprint_id
                    log_activity(cur, issue_id, user_id, "SPRINT_ASSIGNED", f"Assigned to sprint {s_name}")
                else:
                    log_activity(cur, issue_id, user_id, "SPRINT_ASSIGNED", "Removed from sprint")

            cur.execute("""
                UPDATE issues SET
                    project_id = %s,
                    title = %s,
                    description = %s,
                    issue_type = %s,
                    severity = %s,
                    priority = %s,
                    status = %s,
                    assigned_to = %s,
                    sprint_id = %s,
                    component = %s,
                    environment = %s,
                    steps_to_reproduce = %s,
                    expected_result = %s,
                    actual_result = %s,
                    resolution_summary = %s,
                    root_cause = %s,
                    updated_date = %s
                WHERE issue_id = %s
            """, (
                project_id, title, description, issue_type, severity, priority,
                status, assigned_to, sprint_id, component, environment, steps_to_reproduce,
                expected_result, actual_result, resolution_summary, root_cause,
                updated_date, issue_id
            ))
            conn.commit()

        flash(f"Issue {issue_id} updated successfully.", "success")
        return redirect(url_for("issue_detail", issue_id=issue_id))

    with conn.cursor() as cur:
        cur.execute("SELECT project_id, project_name FROM projects ORDER BY project_name")
        projects = cur.fetchall()

        cur.execute("SELECT user_id, display_name, role FROM users WHERE active = TRUE ORDER BY display_name")
        users = cur.fetchall()

        cur.execute("SELECT state_name FROM workflow_states ORDER BY sequence")
        workflow_states = [row["state_name"] for row in cur.fetchall()]

        cur.execute("""
            SELECT s.sprint_id, s.sprint_name, s.status, p.project_name 
            FROM sprints s 
            JOIN projects p ON s.project_id = p.project_id 
            ORDER BY s.sprint_id
        """)
        sprints = cur.fetchall()

    return render_template(
        "issues/edit.html",
        active_page="issues",
        issue=issue,
        projects=projects,
        users=users,
        workflow_states=workflow_states,
        sprints=sprints,
    )


@app.route("/issues/<issue_id>/status", methods=["POST"])
@login_required
def issue_update_status(issue_id):
    new_status = request.form.get("status", "").strip()
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT i.issue_id, i.status, i.assigned_to, i.created_by, i.project_id, p.project_manager_id
            FROM issues i
            JOIN projects p ON i.project_id = p.project_id
            WHERE i.issue_id = %s
        """, (issue_id,))
        issue = cur.fetchone()

        if not issue:
            flash("Issue not found.", "danger")
            return redirect(url_for("issues_list"))

        role = session.get("role")
        user_id = session.get("user_id")
        can_update = (
            role in ["ADMIN", "PROJECT_MANAGER"] or
            (role == "DEVELOPER" and issue["assigned_to"] == user_id) or
            (role == "TESTER")
        )
        if not can_update:
            flash("You do not have permission to change the status of this issue.", "danger")
            return redirect(url_for("issue_detail", issue_id=issue_id))

        old_status = issue["status"]
        allowed = WORKFLOW_TRANSITIONS.get(old_status, [])
        if new_status not in allowed:
            flash(
                f"Invalid workflow transition: Cannot move from '{old_status}' to '{new_status}'. "
                f"Permitted next status: {', '.join(allowed) or 'None (terminal)'}.",
                "danger"
            )
            return redirect(request.referrer or url_for("issue_detail", issue_id=issue_id))

        cur.execute("""
            UPDATE issues 
            SET status = %s, updated_date = CURRENT_DATE 
            WHERE issue_id = %s
        """, (new_status, issue_id))

        log_activity(
            cur, issue_id, user_id, "STATUS_CHANGED",
            f"Status changed from {old_status} to {new_status}",
            old_value=old_status, new_value=new_status
        )
        conn.commit()

    flash(f"Status for {issue_id} updated to {new_status}.", "success")
    return redirect(request.referrer or url_for("issue_detail", issue_id=issue_id))


# ---------------------------------------------------------------------------
# Module 2: Collaboration & Comments Routes
# ---------------------------------------------------------------------------
@app.route("/issues/<issue_id>/comments", methods=["POST"])
@login_required
def issue_add_comment(issue_id):
    comment_text = request.form.get("comment_text", "").strip()
    if not comment_text:
        flash("Comment cannot be empty.", "warning")
        return redirect(url_for("issue_detail", issue_id=issue_id))

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT issue_id FROM issues WHERE issue_id = %s", (issue_id,))
        if not cur.fetchone():
            flash(f"Issue {issue_id} not found.", "danger")
            return redirect(url_for("issues_list"))

        cur.execute("""
            INSERT INTO comments (issue_id, user_id, comment_text, created_at)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
        """, (issue_id, session["user_id"], comment_text))

        author_name = session.get("display_name", "User")
        log_activity(
            cur, issue_id, session["user_id"], "COMMENT_ADDED",
            f"Comment added by {author_name}"
        )
        conn.commit()

    flash("Comment posted successfully.", "success")
    return redirect(url_for("issue_detail", issue_id=issue_id) + "#comments")


@app.route("/issues/<issue_id>/attachments", methods=["POST"])
@login_required
def issue_upload_attachment(issue_id):
    if "file" not in request.files:
        flash("No file was selected for upload.", "warning")
        return redirect(url_for("issue_detail", issue_id=issue_id))

    file = request.files["file"]
    if not file or not file.filename:
        flash("Please select a valid file to upload.", "warning")
        return redirect(url_for("issue_detail", issue_id=issue_id))

    if not allowed_file(file.filename):
        flash("Unsupported file type. Permitted formats: PNG, JPG, JPEG, PDF, TXT.", "danger")
        return redirect(url_for("issue_detail", issue_id=issue_id))

    file_bytes = file.read()
    if len(file_bytes) > MAX_UPLOAD_SIZE:
        flash("File exceeds the maximum upload limit of 5 MB.", "danger")
        return redirect(url_for("issue_detail", issue_id=issue_id))

    safe_original_name = secure_filename(file.filename) or "attachment"
    ext = safe_original_name.rsplit(".", 1)[1].lower() if "." in safe_original_name else "bin"
    stored_filename = f"{secrets.token_hex(8)}_{int(datetime.datetime.now().timestamp())}.{ext}"
    target_path = os.path.abspath(os.path.join(app.config["UPLOAD_FOLDER"], stored_filename))

    # Path traversal safeguard
    if not target_path.startswith(os.path.abspath(app.config["UPLOAD_FOLDER"])):
        flash("Security error: invalid storage path detected.", "danger")
        return redirect(url_for("issue_detail", issue_id=issue_id))

    with open(target_path, "wb") as f:
        f.write(file_bytes)

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO attachments (
                issue_id, user_id, original_filename, stored_filename, file_size, content_type, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """, (
            issue_id, session["user_id"], file.filename, stored_filename,
            len(file_bytes), file.mimetype or "application/octet-stream"
        ))

        uploader_name = session.get("display_name", "User")
        log_activity(
            cur, issue_id, session["user_id"], "ATTACHMENT_ADDED",
            f"Attachment uploaded by {uploader_name}: {file.filename}"
        )
        conn.commit()

    flash(f"Attachment '{file.filename}' uploaded successfully.", "success")
    return redirect(url_for("issue_detail", issue_id=issue_id) + "#attachments")


@app.route("/issues/<issue_id>/attachments/<int:attachment_id>/download")
@login_required
def issue_download_attachment(issue_id, attachment_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT original_filename, stored_filename, content_type
            FROM attachments
            WHERE attachment_id = %s AND issue_id = %s
        """, (attachment_id, issue_id))
        att = cur.fetchone()

        if not att:
            flash("Attachment not found or access denied.", "danger")
            return redirect(url_for("issue_detail", issue_id=issue_id))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        att["stored_filename"],
        as_attachment=True,
        download_name=att["original_filename"]
    )


@app.route("/issues/<issue_id>/delete", methods=["POST"])
@login_required
def issue_delete(issue_id):
    role = session.get("role")
    user_id = session.get("user_id")
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute("""
            SELECT i.issue_id, p.project_manager_id 
            FROM issues i 
            JOIN projects p ON i.project_id = p.project_id 
            WHERE i.issue_id = %s
        """, (issue_id,))
        issue = cur.fetchone()

        if not issue:
            flash(f"Issue {issue_id} not found.", "danger")
            return redirect(url_for("issues_list"))

        if role != "ADMIN" and (role != "PROJECT_MANAGER" or issue["project_manager_id"] != user_id):
            flash("You do not have permission to delete this issue.", "danger")
            return redirect(url_for("issue_detail", issue_id=issue_id))

        # Check if other issues reference this one as duplicate
        cur.execute("SELECT issue_id FROM issues WHERE duplicate_of_issue_id = %s", (issue_id,))
        referencing = cur.fetchall()
        if referencing:
            ref_ids = ", ".join(r["issue_id"] for r in referencing)
            flash(f"Cannot delete issue {issue_id}: referenced by duplicates ({ref_ids}).", "warning")
            return redirect(url_for("issue_detail", issue_id=issue_id))

        # Safely remove resolution suggestions first to prevent FK constraint error
        cur.execute("DELETE FROM resolution_suggestions WHERE issue_id = %s", (issue_id,))
        cur.execute("DELETE FROM issues WHERE issue_id = %s", (issue_id,))
        conn.commit()

    flash(f"Issue {issue_id} and its associated suggestions have been deleted.", "success")
    return redirect(url_for("issues_list"))


# ---------------------------------------------------------------------------
# Project Management Routes
# ---------------------------------------------------------------------------
@app.route("/projects")
@login_required
def projects_list():
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT 
                p.project_id, p.project_name, p.description, p.created_date, p.lifecycle_status,
                u.display_name AS manager_name,
                COUNT(i.issue_id) AS issue_count
            FROM projects p
            LEFT JOIN users u ON p.project_manager_id = u.user_id
            LEFT JOIN issues i ON p.project_id = i.project_id
            GROUP BY p.project_id, p.project_name, p.description, p.created_date, p.lifecycle_status, u.display_name
            ORDER BY p.project_id ASC
        """)
        projects = cur.fetchall()

        cur.execute("SELECT user_id, display_name, email FROM users WHERE role = 'PROJECT_MANAGER' AND active = TRUE")
        managers = cur.fetchall()

    return render_template("projects/list.html", active_page="projects", projects=projects, managers=managers)


@app.route("/projects/create", methods=["POST"])
@login_required
@roles_required("ADMIN")
def project_create():
    project_name = request.form.get("project_name", "").strip()
    description = request.form.get("description", "").strip()
    project_manager_id = request.form.get("project_manager_id", "").strip() or None

    if not project_name:
        flash("Project name is required.", "danger")
        return redirect(url_for("projects_list"))

    conn = get_db()
    with conn.cursor() as cur:
        next_pid = get_next_id(cur, "projects", "project_id", "PRJ", 3)
        created_date = datetime.date.today()

        cur.execute("""
            INSERT INTO projects (project_id, project_name, description, created_date, project_manager_id, lifecycle_status)
            VALUES (%s, %s, %s, %s, %s, 'ACTIVE')
        """, (next_pid, project_name, description, created_date, project_manager_id))
        conn.commit()

    flash(f"Project '{project_name}' ({next_pid}) created successfully.", "success")
    return redirect(url_for("project_detail", project_id=next_pid))


@app.route("/projects/<project_id>")
@login_required
def project_detail(project_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT p.*, u.display_name AS manager_name
            FROM projects p
            LEFT JOIN users u ON p.project_manager_id = u.user_id
            WHERE p.project_id = %s
        """, (project_id,))
        project = cur.fetchone()

        if not project:
            flash(f"Project {project_id} not found.", "danger")
            return redirect(url_for("projects_list"))

        cur.execute("""
            SELECT sprint_id, sprint_name, start_date, end_date, status
            FROM sprints
            WHERE project_id = %s
            ORDER BY sprint_id ASC
        """, (project_id,))
        sprints = cur.fetchall()

        cur.execute("""
            SELECT issue_id, title, status, priority
            FROM issues
            WHERE project_id = %s
            ORDER BY issue_id DESC
        """, (project_id,))
        issues = cur.fetchall()

    return render_template(
        "projects/detail.html",
        active_page="projects",
        project=project,
        sprints=sprints,
        issues=issues,
    )


# ---------------------------------------------------------------------------
# User & Role Management Routes (Admin Only)
# ---------------------------------------------------------------------------
@app.route("/users")
@login_required
@roles_required("ADMIN")
def users_list():
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT user_id, display_name, email, role, active,
                   (password_hash IS NOT NULL) AS has_password
            FROM users
            ORDER BY user_id ASC
        """)
        users = cur.fetchall()

    return render_template("users/list.html", active_page="users", users=users)


@app.route("/users/create", methods=["POST"])
@login_required
@roles_required("ADMIN")
def user_create():
    display_name = request.form.get("display_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "DEVELOPER")
    password = request.form.get("password", "")

    if not display_name or not email or not password:
        flash("Name, email, and password are required.", "danger")
        return redirect(url_for("users_list"))

    if role not in ROLES:
        flash("Invalid role selected.", "danger")
        return redirect(url_for("users_list"))

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT user_id FROM users WHERE LOWER(email) = %s", (email,))
        if cur.fetchone():
            flash("User with this email already exists.", "danger")
            return redirect(url_for("users_list"))

        next_uid = get_next_id(cur, "users", "user_id", "USR", 3)
        password_hash = generate_password_hash(password)

        cur.execute("""
            INSERT INTO users (user_id, display_name, email, role, active, password_hash)
            VALUES (%s, %s, %s, %s, TRUE, %s)
        """, (next_uid, display_name, email, role, password_hash))
        conn.commit()

    flash(f"User {display_name} ({next_uid}) created successfully.", "success")
    return redirect(url_for("users_list"))


@app.route("/users/<user_id>/update", methods=["POST"])
@login_required
@roles_required("ADMIN")
def user_update(user_id):
    new_role = request.form.get("role")
    active = bool(request.form.get("active"))

    if new_role not in ROLES:
        flash("Invalid role.", "danger")
        return redirect(url_for("users_list"))

    # Protect against admin demoting or deactivating their own active session
    if user_id == session.get("user_id"):
        if not active:
            flash("You cannot deactivate your own current administrator account.", "danger")
            return redirect(url_for("users_list"))

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE users 
            SET role = %s, active = %s 
            WHERE user_id = %s
        """, (new_role, active, user_id))
        conn.commit()

    flash(f"User {user_id} updated.", "success")
    return redirect(url_for("users_list"))


@app.route("/users/<user_id>/password", methods=["POST"])
@login_required
@roles_required("ADMIN")
def user_set_password(user_id):
    new_password = request.form.get("password", "")
    if len(new_password) < 6:
        flash("Password must be at least 6 characters long.", "danger")
        return redirect(url_for("users_list"))

    password_hash = generate_password_hash(new_password)
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET password_hash = %s WHERE user_id = %s", (password_hash, user_id))
        conn.commit()

    flash(f"Password updated for user {user_id}.", "success")
    return redirect(url_for("users_list"))


# ---------------------------------------------------------------------------
# Module 3: Sprint Planning & Backlog Management Routes
# ---------------------------------------------------------------------------
@app.route("/sprints")
@login_required
def sprints_list():
    selected_project = request.args.get("project_id", "").strip()
    conn = get_db()

    with conn.cursor() as cur:
        cur.execute("SELECT project_id, project_name FROM projects ORDER BY project_name")
        projects = cur.fetchall()

        where_clause = "WHERE s.project_id = %s" if selected_project else ""
        params = [selected_project] if selected_project else []

        sprint_sql = f"""
            SELECT 
                s.sprint_id, s.sprint_name, s.project_id, s.start_date, s.end_date, s.status,
                p.project_name,
                COUNT(i.issue_id) AS issue_count,
                COUNT(i.issue_id) FILTER (WHERE i.status IN ('Resolved', 'Closed')) AS completed_count,
                COUNT(i.issue_id) FILTER (WHERE i.status IN ('In Progress', 'Testing')) AS in_progress_count,
                COUNT(i.issue_id) FILTER (WHERE i.status = 'Open') AS remaining_count
            FROM sprints s
            JOIN projects p ON s.project_id = p.project_id
            LEFT JOIN issues i ON s.sprint_id = i.sprint_id
            {where_clause}
            GROUP BY s.sprint_id, s.sprint_name, s.project_id, s.start_date, s.end_date, s.status, p.project_name
            ORDER BY s.sprint_id ASC
        """
        cur.execute(sprint_sql, params)
        sprints = cur.fetchall()

    return render_template(
        "sprints/list.html",
        active_page="sprints",
        sprints=sprints,
        projects=projects,
        selected_project=selected_project,
    )


@app.route("/sprints/create", methods=["POST"])
@login_required
@roles_required("ADMIN", "PROJECT_MANAGER")
def sprint_create():
    sprint_name = request.form.get("sprint_name", "").strip()
    project_id = request.form.get("project_id", "").strip()
    start_date = request.form.get("start_date", "").strip()
    end_date = request.form.get("end_date", "").strip()

    if not sprint_name or not project_id or not start_date or not end_date:
        flash("Sprint name, project, start date, and end date are required.", "danger")
        return redirect(url_for("sprints_list"))

    try:
        sd = datetime.date.fromisoformat(start_date)
        ed = datetime.date.fromisoformat(end_date)
        if ed < sd:
            flash("Sprint end date cannot be earlier than start date.", "danger")
            return redirect(url_for("sprints_list"))
    except ValueError:
        flash("Invalid date format provided. Expected YYYY-MM-DD.", "danger")
        return redirect(url_for("sprints_list"))

    conn = get_db()
    with conn.cursor() as cur:
        # Check project existence
        cur.execute("SELECT project_id, project_name FROM projects WHERE project_id = %s", (project_id,))
        proj = cur.fetchone()
        if not proj:
            flash("Specified project does not exist.", "danger")
            return redirect(url_for("sprints_list"))

        new_sprint_id = generate_sprint_id(cur, project_id)

        cur.execute("""
            INSERT INTO sprints (sprint_id, project_id, sprint_name, start_date, end_date, status)
            VALUES (%s, %s, %s, %s, %s, 'ACTIVE')
        """, (new_sprint_id, project_id, sprint_name, sd, ed))
        conn.commit()

    flash(f"Sprint '{sprint_name}' ({new_sprint_id}) created successfully!", "success")
    return redirect(url_for("sprint_board", sprint_id=new_sprint_id))


@app.route("/sprints/<sprint_id>")
@login_required
def sprint_board(sprint_id):
    conn = get_db()
    with conn.cursor() as cur:
        # Fetch sprint info
        cur.execute("""
            SELECT s.*, p.project_name
            FROM sprints s
            JOIN projects p ON s.project_id = p.project_id
            WHERE s.sprint_id = %s
        """, (sprint_id,))
        sprint = cur.fetchone()

        if not sprint:
            flash(f"Sprint {sprint_id} not found.", "danger")
            return redirect(url_for("sprints_list"))

        # Fetch assigned sprint issues
        cur.execute("""
            SELECT 
                i.issue_id, i.title, i.issue_type, i.priority, i.severity, i.status,
                i.component, i.assigned_to, u.display_name AS assignee_name, i.created_date
            FROM issues i
            LEFT JOIN users u ON i.assigned_to = u.user_id
            WHERE i.sprint_id = %s
            ORDER BY i.priority ASC, i.issue_id ASC
        """, (sprint_id,))
        sprint_issues = cur.fetchall()

        # Three-column grouping per Milestone 2 PPT
        todo_issues = [i for i in sprint_issues if i["status"] == "Open"]
        in_progress_issues = [i for i in sprint_issues if i["status"] in ["In Progress", "Testing"]]
        done_issues = [i for i in sprint_issues if i["status"] in ["Resolved", "Closed"]]

        # Fetch unassigned backlog issues for this sprint's project
        q = request.args.get("q", "").strip()
        backlog_where = ["i.sprint_id IS NULL", "i.project_id = %s"]
        backlog_params = [sprint["project_id"]]
        if q:
            backlog_where.append("(i.issue_id ILIKE %s OR i.title ILIKE %s)")
            backlog_params.extend([f"%{q}%", f"%{q}%"])

        cur.execute(f"""
            SELECT 
                i.issue_id, i.title, i.issue_type, i.priority, i.severity, i.status,
                i.component, i.assigned_to, u.display_name AS assignee_name
            FROM issues i
            LEFT JOIN users u ON i.assigned_to = u.user_id
            WHERE {' AND '.join(backlog_where)}
            ORDER BY i.issue_id DESC
        """, backlog_params)
        backlog_issues = cur.fetchall()

    return render_template(
        "sprints/board.html",
        active_page="sprints",
        sprint=sprint,
        todo_issues=todo_issues,
        in_progress_issues=in_progress_issues,
        done_issues=done_issues,
        backlog_issues=backlog_issues,
        total_count=len(sprint_issues),
        search_q=q,
    )


@app.route("/sprints/<sprint_id>/assign", methods=["POST"])
@login_required
@roles_required("ADMIN", "PROJECT_MANAGER")
def sprint_assign_issue(sprint_id):
    issue_id = request.form.get("issue_id", "").strip()
    conn = get_db()
    with conn.cursor() as cur:
        # Validate sprint
        cur.execute("SELECT sprint_id, project_id, sprint_name FROM sprints WHERE sprint_id = %s", (sprint_id,))
        sprint = cur.fetchone()
        if not sprint:
            flash("Sprint not found.", "danger")
            return redirect(url_for("sprints_list"))

        # Validate issue
        cur.execute("SELECT issue_id, project_id, title FROM issues WHERE issue_id = %s", (issue_id,))
        issue = cur.fetchone()
        if not issue:
            flash(f"Issue {issue_id} not found.", "danger")
            return redirect(url_for("sprint_board", sprint_id=sprint_id))

        # Enforce that issue and sprint belong to the same project
        if issue["project_id"] != sprint["project_id"]:
            flash(
                f"Project mismatch: Issue {issue_id} belongs to project {issue['project_id']}, "
                f"while sprint {sprint_id} belongs to {sprint['project_id']}.",
                "danger"
            )
            return redirect(request.referrer or url_for("sprint_board", sprint_id=sprint_id))

        cur.execute("UPDATE issues SET sprint_id = %s WHERE issue_id = %s", (sprint_id, issue_id))
        log_activity(
            cur, issue_id, session["user_id"], "SPRINT_ASSIGNED",
            f"Assigned to sprint {sprint['sprint_name']} ({sprint_id})"
        )
        conn.commit()

    flash(f"Issue {issue_id} assigned to sprint {sprint['sprint_name']}.", "success")
    return redirect(request.referrer or url_for("sprint_board", sprint_id=sprint_id))


@app.route("/sprints/<sprint_id>/remove/<issue_id>", methods=["POST"])
@login_required
@roles_required("ADMIN", "PROJECT_MANAGER")
def sprint_remove_issue(sprint_id, issue_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT sprint_name FROM sprints WHERE sprint_id = %s", (sprint_id,))
        sprint = cur.fetchone()
        s_name = sprint["sprint_name"] if sprint else sprint_id

        cur.execute("UPDATE issues SET sprint_id = NULL WHERE issue_id = %s AND sprint_id = %s", (issue_id, sprint_id))
        log_activity(
            cur, issue_id, session["user_id"], "SPRINT_ASSIGNED",
            f"Removed from sprint {s_name}"
        )
        conn.commit()

    flash(f"Issue {issue_id} removed from sprint.", "info")
    return redirect(request.referrer or url_for("sprint_board", sprint_id=sprint_id))


@app.route("/backlog")
@login_required
def backlog_list():
    selected_project = request.args.get("project_id", "").strip()
    q = request.args.get("q", "").strip()
    conn = get_db()

    conditions = ["i.sprint_id IS NULL"]
    params = []

    if selected_project:
        conditions.append("i.project_id = %s")
        params.append(selected_project)

    if q:
        conditions.append("(i.issue_id ILIKE %s OR i.title ILIKE %s OR i.component ILIKE %s)")
        search_pattern = f"%{q}%"
        params.extend([search_pattern, search_pattern, search_pattern])

    where_sql = "WHERE " + " AND ".join(conditions)

    with conn.cursor() as cur:
        # Fetch backlog issues
        cur.execute(f"""
            SELECT 
                i.issue_id, i.title, i.issue_type, i.priority, i.severity, i.status,
                i.component, i.project_id, p.project_name,
                i.assigned_to, u.display_name AS assignee_name, i.created_date
            FROM issues i
            JOIN projects p ON i.project_id = p.project_id
            LEFT JOIN users u ON i.assigned_to = u.user_id
            {where_sql}
            ORDER BY i.priority ASC, i.issue_id DESC
        """, params)
        backlog_issues = cur.fetchall()

        # Fetch projects for filter
        cur.execute("SELECT project_id, project_name FROM projects ORDER BY project_name")
        projects = cur.fetchall()

        # Fetch active sprints for quick assignment
        cur.execute("""
            SELECT s.sprint_id, s.sprint_name, s.project_id, p.project_name
            FROM sprints s
            JOIN projects p ON s.project_id = p.project_id
            ORDER BY s.project_id, s.sprint_name
        """)
        sprints = cur.fetchall()

    return render_template(
        "sprints/backlog.html",
        active_page="backlog",
        backlog_issues=backlog_issues,
        projects=projects,
        sprints=sprints,
        selected_project=selected_project,
        q=q,
    )


# ---------------------------------------------------------------------------
# Analytical Reports Route
# ---------------------------------------------------------------------------
@app.route("/reports")
@login_required
@roles_required("ADMIN", "PROJECT_MANAGER", "TESTER")
def reports_view():
    conn = get_db()
    with conn.cursor() as cur:
        status_colors = {"Open": "#ef4444", "In Progress": "#f59e0b", "Testing": "#8b5cf6", "Resolved": "#10b981", "Closed": "#64748b"}
        sev_colors = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#d97706", "Low": "#2563eb"}

        def fetch_report_group(column, colors=None, default_color="#2563eb", order_sql="count DESC"):
            query = sql.SQL(
                "SELECT {col} AS name, "
                "COUNT(*) AS count, "
                "COALESCE(ROUND(COUNT(*) * 100.0 / NULLIF(SUM(COUNT(*)) OVER(), 0), 1), 0) AS percent "
                "FROM issues "
                "GROUP BY {col} "
                "ORDER BY "
            ).format(col=sql.Identifier(column)) + sql.SQL(order_sql)
            cur.execute(query)
            rows = cur.fetchall()
            if colors is not None:
                for r in rows:
                    r["color"] = colors.get(r["name"], default_color)
            return rows

        status_counts = fetch_report_group("status", status_colors, default_color="#3b82f6")
        severity_counts = fetch_report_group("severity", sev_colors, default_color="#64748b")
        priority_counts = fetch_report_group("priority", colors={}, default_color="#2563eb", order_sql="priority ASC")
        type_counts = fetch_report_group("issue_type")

        # Project breakdown
        cur.execute("""
            SELECT 
                p.project_name,
                COUNT(i.issue_id) AS total_count,
                COUNT(i.issue_id) FILTER (WHERE i.status = 'Open') AS open_count,
                COUNT(i.issue_id) FILTER (WHERE i.status = 'In Progress') AS in_progress_count,
                COUNT(i.issue_id) FILTER (WHERE i.status = 'Testing') AS testing_count,
                COUNT(i.issue_id) FILTER (WHERE i.status IN ('Resolved', 'Closed')) AS resolved_count
            FROM projects p
            LEFT JOIN issues i ON p.project_id = i.project_id
            GROUP BY p.project_name
            ORDER BY total_count DESC
        """)
        project_breakdown = cur.fetchall()

    return render_template(
        "reports/index.html",
        active_page="reports",
        status_counts=status_counts,
        severity_counts=severity_counts,
        priority_counts=priority_counts,
        type_counts=type_counts,
        project_breakdown=project_breakdown,
    )


# ---------------------------------------------------------------------------
# Database & Settings Route (Admin Only)
# ---------------------------------------------------------------------------
@app.route("/settings/database")
@login_required
@roles_required("ADMIN")
def database_status():
    conn = get_db()
    with conn.cursor() as cur:
        table_specs = [
            ("users", "User accounts, role assignments, and authentication"),
            ("projects", "Product work streams and project manager associations"),
            ("workflow_states", "Standard state definitions and lifecycle sequences"),
            ("sprints", "Sprint release cycles belonging to projects"),
            ("issues", "Comprehensive defect records, descriptions, and metadata"),
            ("resolution_suggestions", "Synthetic rule-based illustrative suggestions"),
        ]

        table_counts = []
        total_records = 0
        for tbl, desc in table_specs:
            cur.execute(sql.SQL("SELECT COUNT(*) AS count FROM {tbl}").format(tbl=sql.Identifier(tbl)))
            cnt = cur.fetchone()["count"]
            total_records += cnt
            table_counts.append({"table": tbl, "desc": desc, "count": cnt})

    return render_template(
        "settings/database.html",
        active_page="database",
        table_counts=table_counts,
        total_records=total_records,
        app_version="3.1.3",
        python_version=sys.version.split()[0],
    )


# ---------------------------------------------------------------------------
# Milestone 3: Module 1 — REST API Helpers & Endpoints
# ---------------------------------------------------------------------------
def serialize_issue(row):
    """Serializes a database issue record for JSON responses."""
    if not row:
        return None
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, (datetime.date, datetime.datetime)):
            d[k] = v.isoformat()
    return d


def get_current_api_user():
    """Resolves authenticated user and auth type from test header, session, or HTTP Basic Auth."""
    # 1. Test-only identity header for automated unit tests
    if app.config.get("TESTING") and request.headers.get("X-Test-User-ID"):
        test_uid = request.headers.get("X-Test-User-ID")
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, email, role, display_name, active "
                "FROM users WHERE user_id = %s",
                (test_uid,)
            )
            user = cur.fetchone()
            if user and user["active"]:
                return {
                    "user_id": user["user_id"],
                    "role": user["role"],
                    "email": user["email"],
                    "display_name": user["display_name"],
                }, "test_header"

    # 2. HTTP Basic Auth credentials (header-based authentication)
    auth = request.authorization
    if auth and auth.username and auth.password:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, email, password_hash, role, display_name, active "
                "FROM users WHERE email = %s",
                (auth.username,)
            )
            user = cur.fetchone()
            if user and user["active"] and check_password_hash(user["password_hash"], auth.password):
                return {
                    "user_id": user["user_id"],
                    "role": user["role"],
                    "email": user["email"],
                    "display_name": user["display_name"],
                }, "basic_auth"

    # 3. Active Flask session (cookie-based authentication)
    if "user_id" in session:
        return {
            "user_id": session.get("user_id"),
            "role": session.get("role"),
            "email": session.get("email"),
            "display_name": session.get("display_name"),
        }, "session"

    return None, None


def api_login_required(f):
    """Enforces authentication and session-CSRF protection for REST API endpoints."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        user, auth_type = get_current_api_user()
        if not user:
            return jsonify({
                "success": False,
                "error": "Unauthorized",
                "message": "Authentication required. Please log in or provide valid credentials."
            }), 401

        # CSRF Protection: When authenticated via session cookies, state-changing requests
        # must provide a matching CSRF token via 'X-CSRF-Token' header or 'csrf_token' field
        if auth_type == "session" and request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            token = request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRFToken")
            if not token and request.is_json:
                body = request.get_json(silent=True)
                if isinstance(body, dict):
                    token = body.get("csrf_token")

            expected = session.get("csrf_token")
            if not token or not expected or not secrets.compare_digest(str(token), str(expected)):
                return jsonify({
                    "success": False,
                    "error": "CSRF Error",
                    "message": "Valid CSRF token required for session-authenticated API requests. Provide 'X-CSRF-Token' header or 'csrf_token' field."
                }), 403

        return f(user, *args, **kwargs)
    return decorated_function


# 1. GET /api/issues
@app.route("/api/issues", methods=["GET"])
@api_login_required
def api_issues_list(user):
    """Retrieve issues with optional filters for status, priority, severity and project_id."""
    status = request.args.get("status")
    priority = request.args.get("priority")
    severity = request.args.get("severity")
    project_id = request.args.get("project_id")

    query_parts = ["""
        SELECT i.*, p.project_name,
               u_assigned.display_name AS assignee_name,
               u_created.display_name AS creator_name
        FROM issues i
        JOIN projects p ON i.project_id = p.project_id
        LEFT JOIN users u_assigned ON i.assigned_to = u_assigned.user_id
        LEFT JOIN users u_created ON i.created_by = u_created.user_id
        WHERE 1=1
    """]
    params = []

    if status:
        query_parts.append("AND i.status = %s")
        params.append(status)
    if priority:
        query_parts.append("AND i.priority = %s")
        params.append(priority)
    if severity:
        query_parts.append("AND i.severity = %s")
        params.append(severity)
    if project_id:
        query_parts.append("AND i.project_id = %s")
        params.append(project_id)

    query_parts.append("ORDER BY i.created_date DESC, i.issue_id DESC")

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(" ".join(query_parts), params)
        issues = cur.fetchall()

    return jsonify({
        "success": True,
        "count": len(issues),
        "issues": [serialize_issue(r) for r in issues]
    }), 200


# 2. GET /api/issues/<issue_id>
@app.route("/api/issues/<issue_id>", methods=["GET"])
@api_login_required
def api_issue_detail(user, issue_id):
    """Retrieve details for a single issue by ID."""
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT i.*, p.project_name, p.project_manager_id,
                   u_assigned.display_name AS assignee_name,
                   u_created.display_name AS creator_name
            FROM issues i
            JOIN projects p ON i.project_id = p.project_id
            LEFT JOIN users u_assigned ON i.assigned_to = u_assigned.user_id
            LEFT JOIN users u_created ON i.created_by = u_created.user_id
            WHERE i.issue_id = %s
        """, (issue_id,))
        issue = cur.fetchone()

    if not issue:
        return jsonify({
            "success": False,
            "error": "Not Found",
            "message": f"Issue '{issue_id}' not found."
        }), 404

    return jsonify({
        "success": True,
        "issue": serialize_issue(issue)
    }), 200


# 3. POST /api/issues
@app.route("/api/issues", methods=["POST"])
@api_login_required
def api_issue_create(user):
    """Create a new issue with server-side validation and sequential ID generation."""
    if user["role"] not in ["ADMIN", "PROJECT_MANAGER", "TESTER"]:
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "Only administrators, project managers, and testers can create new issues."
        }), 403

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Bad Request",
            "message": "Request body must be a valid JSON object."
        }), 400

    allowed_post_fields = {
        "project_id", "title", "description", "issue_type", "severity",
        "priority", "assigned_to", "sprint_id", "component", "environment",
        "steps_to_reproduce", "expected_result", "actual_result", "business_impact"
    }
    unexpected = set(data.keys()) - allowed_post_fields - {"csrf_token"}
    if unexpected:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": f"Unexpected fields in request: {', '.join(sorted(unexpected))}."
        }), 400

    project_id = str(data.get("project_id", "")).strip()
    title = str(data.get("title", "")).strip()
    description = str(data.get("description", "")).strip()
    issue_type = str(data.get("issue_type", "Bug")).strip()
    severity = str(data.get("severity", "Medium")).strip()
    priority = str(data.get("priority", "P2")).strip()
    assigned_to = data.get("assigned_to")
    if assigned_to:
        assigned_to = str(assigned_to).strip()
    sprint_id = data.get("sprint_id")
    if sprint_id:
        sprint_id = str(sprint_id).strip()

    component = data.get("component")
    environment = data.get("environment")
    steps_to_reproduce = data.get("steps_to_reproduce")
    expected_result = data.get("expected_result")
    actual_result = data.get("actual_result")
    business_impact = data.get("business_impact")

    # Validate required fields
    if not project_id or not title or not description:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": "project_id, title, and description are required fields."
        }), 400

    if issue_type not in NEW_ISSUE_TYPES:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": f"Invalid issue_type. Must be one of: {', '.join(NEW_ISSUE_TYPES)}"
        }), 400

    if severity not in SEVERITIES:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": f"Invalid severity. Must be one of: {', '.join(SEVERITIES)}"
        }), 400

    if priority not in NEW_PRIORITIES:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": f"Invalid priority. Must be one of: {', '.join(NEW_PRIORITIES)}"
        }), 400

    conn = get_db()
    with conn.cursor() as cur:
        # Check project existence and manager scope
        cur.execute("SELECT project_id, project_manager_id FROM projects WHERE project_id = %s", (project_id,))
        prj_row = cur.fetchone()
        if not prj_row:
            return jsonify({
                "success": False,
                "error": "Validation Error",
                "message": f"Project '{project_id}' does not exist."
            }), 400

        if user["role"] == "PROJECT_MANAGER" and prj_row["project_manager_id"] != user["user_id"]:
            return jsonify({
                "success": False,
                "error": "Forbidden",
                "message": "Project managers can only create issues within projects they manage."
            }), 403

        # Check assigned user if given
        assignee_name = None
        if assigned_to:
            cur.execute("SELECT user_id, display_name, active FROM users WHERE user_id = %s", (assigned_to,))
            u_row = cur.fetchone()
            if not u_row or not u_row["active"]:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": f"Assigned user '{assigned_to}' is invalid or inactive."
                }), 400
            assignee_name = u_row["display_name"]

        # Check sprint if given and enforce project consistency
        if sprint_id:
            cur.execute("SELECT sprint_id, project_id FROM sprints WHERE sprint_id = %s", (sprint_id,))
            sprint_row = cur.fetchone()
            if not sprint_row:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": f"Sprint '{sprint_id}' does not exist."
                }), 400
            if sprint_row["project_id"] != project_id:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": f"Sprint '{sprint_id}' belongs to project '{sprint_row['project_id']}', not '{project_id}'."
                }), 400

        # Generate next sequential ID
        next_issue_id = get_next_id(cur, "issues", "issue_id", "BUG", 5)
        created_date = datetime.date.today()
        status = "Open"

        cur.execute("""
            INSERT INTO issues (
                issue_id, title, description, issue_type, severity, priority,
                status, project_id, assigned_to, created_by, created_date,
                updated_date, component, environment, steps_to_reproduce,
                expected_result, actual_result, business_impact, sprint_id
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s
            )
        """, (
            next_issue_id, title, description, issue_type, severity, priority,
            status, project_id, assigned_to, user["user_id"], created_date,
            created_date, component, environment, steps_to_reproduce,
            expected_result, actual_result, business_impact, sprint_id
        ))

        log_activity(cur, next_issue_id, user["user_id"], "CREATED", "Issue created via REST API")
        if assigned_to and assignee_name:
            log_activity(cur, next_issue_id, user["user_id"], "ASSIGNED", f"Assigned to {assignee_name}", new_value=assignee_name)

        conn.commit()

        cur.execute("""
            SELECT i.*, p.project_name,
                   u_assigned.display_name AS assignee_name,
                   u_created.display_name AS creator_name
            FROM issues i
            JOIN projects p ON i.project_id = p.project_id
            LEFT JOIN users u_assigned ON i.assigned_to = u_assigned.user_id
            LEFT JOIN users u_created ON i.created_by = u_created.user_id
            WHERE i.issue_id = %s
        """, (next_issue_id,))
        created_issue = cur.fetchone()

    return jsonify({
        "success": True,
        "message": "Issue created successfully.",
        "issue_id": next_issue_id,
        "issue": serialize_issue(created_issue)
    }), 201


# 4. PUT /api/issues/<issue_id>
@app.route("/api/issues/<issue_id>", methods=["PUT"])
@api_login_required
def api_issue_update(user, issue_id):
    """Update permitted issue fields with validation."""
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT i.*, p.project_manager_id 
            FROM issues i 
            JOIN projects p ON i.project_id = p.project_id 
            WHERE i.issue_id = %s
        """, (issue_id,))
        issue = cur.fetchone()

        if not issue:
            return jsonify({
                "success": False,
                "error": "Not Found",
                "message": f"Issue '{issue_id}' not found."
            }), 404

        role = user["role"]
        user_id = user["user_id"]
        authorized = (
            role == "ADMIN" or
            (role == "PROJECT_MANAGER" and issue["project_manager_id"] == user_id) or
            (role == "DEVELOPER" and issue["assigned_to"] == user_id) or
            (role == "TESTER" and issue["created_by"] == user_id)
        )
        if not authorized:
            return jsonify({
                "success": False,
                "error": "Forbidden",
                "message": "You are not authorized to update this issue."
            }), 403

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({
                "success": False,
                "error": "Bad Request",
                "message": "Request body must be a valid JSON object."
            }), 400

        allowed_fields = {
            "title", "description", "issue_type", "severity", "priority",
            "component", "environment", "steps_to_reproduce", "expected_result",
            "actual_result", "business_impact", "resolution_summary", "root_cause",
            "assigned_to", "sprint_id", "project_id"
        }

        unexpected = set(data.keys()) - allowed_fields - {"csrf_token"}
        if unexpected:
            return jsonify({
                "success": False,
                "error": "Validation Error",
                "message": f"Unexpected fields in request: {', '.join(sorted(unexpected))}."
            }), 400

        updates = {}
        for k, v in data.items():
            if k in allowed_fields:
                updates[k] = v

        if not updates:
            return jsonify({
                "success": False,
                "error": "Bad Request",
                "message": "No valid updatable fields provided in request."
            }), 400

        # Field validation
        if "title" in updates:
            updates["title"] = str(updates["title"]).strip()
            if not updates["title"]:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": "title cannot be empty."
                }), 400

        if "issue_type" in updates:
            if updates["issue_type"] not in ALL_ISSUE_TYPES:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": f"Invalid issue_type. Must be one of: {', '.join(ALL_ISSUE_TYPES)}"
                }), 400

        if "severity" in updates:
            if updates["severity"] not in SEVERITIES:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": f"Invalid severity. Must be one of: {', '.join(SEVERITIES)}"
                }), 400

        if "priority" in updates:
            if updates["priority"] not in ALL_PRIORITIES:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": f"Invalid priority. Must be one of: {', '.join(ALL_PRIORITIES)}"
                }), 400

        if "project_id" in updates:
            cur.execute("SELECT project_id, project_manager_id FROM projects WHERE project_id = %s", (updates["project_id"],))
            target_prj = cur.fetchone()
            if not target_prj:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": f"Project '{updates['project_id']}' does not exist."
                }), 400
            if role == "PROJECT_MANAGER" and target_prj["project_manager_id"] != user_id:
                return jsonify({
                    "success": False,
                    "error": "Forbidden",
                    "message": "Project managers cannot transfer issues to projects they do not manage."
                }), 403

        if "assigned_to" in updates and updates["assigned_to"]:
            cur.execute("SELECT user_id, active FROM users WHERE user_id = %s", (updates["assigned_to"],))
            u_check = cur.fetchone()
            if not u_check or not u_check["active"]:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": f"Assigned user '{updates['assigned_to']}' is invalid or inactive."
                }), 400

        effective_project_id = updates.get("project_id", issue["project_id"])
        if "sprint_id" in updates and updates["sprint_id"]:
            cur.execute("SELECT sprint_id, project_id FROM sprints WHERE sprint_id = %s", (updates["sprint_id"],))
            sprint_row = cur.fetchone()
            if not sprint_row:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": f"Sprint '{updates['sprint_id']}' does not exist."
                }), 400
            if sprint_row["project_id"] != effective_project_id:
                return jsonify({
                    "success": False,
                    "error": "Validation Error",
                    "message": f"Sprint '{updates['sprint_id']}' belongs to project '{sprint_row['project_id']}', not '{effective_project_id}'."
                }), 400

        set_clauses = [sql.SQL("{col} = %s").format(col=sql.Identifier(col)) for col in updates.keys()]
        set_clauses.append(sql.SQL("updated_date = CURRENT_DATE"))
        query = sql.SQL("UPDATE issues SET {clauses} WHERE issue_id = %s").format(
            clauses=sql.SQL(", ").join(set_clauses)
        )
        params = list(updates.values()) + [issue_id]
        cur.execute(query, params)

        log_activity(cur, issue_id, user["user_id"], "UPDATED", "Issue updated via REST API")
        conn.commit()

        cur.execute("""
            SELECT i.*, p.project_name,
                   u_assigned.display_name AS assignee_name,
                   u_created.display_name AS creator_name
            FROM issues i
            JOIN projects p ON i.project_id = p.project_id
            LEFT JOIN users u_assigned ON i.assigned_to = u_assigned.user_id
            LEFT JOIN users u_created ON i.created_by = u_created.user_id
            WHERE i.issue_id = %s
        """, (issue_id,))
        updated_issue = cur.fetchone()

    return jsonify({
        "success": True,
        "message": "Issue updated successfully.",
        "issue": serialize_issue(updated_issue)
    }), 200


# 5. DELETE /api/issues/<issue_id>
@app.route("/api/issues/<issue_id>", methods=["DELETE"])
@api_login_required
def api_issue_delete(user, issue_id):
    """Safely delete an issue preserving permissions and referential integrity."""
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT i.issue_id, p.project_manager_id 
            FROM issues i 
            JOIN projects p ON i.project_id = p.project_id 
            WHERE i.issue_id = %s
        """, (issue_id,))
        issue = cur.fetchone()

        if not issue:
            return jsonify({
                "success": False,
                "error": "Not Found",
                "message": f"Issue '{issue_id}' not found."
            }), 404

        role = user["role"]
        user_id = user["user_id"]
        if role != "ADMIN" and (role != "PROJECT_MANAGER" or issue["project_manager_id"] != user_id):
            return jsonify({
                "success": False,
                "error": "Forbidden",
                "message": "Only administrators and project managers can delete issues."
            }), 403

        # Prevent deletion if referenced as duplicate by other issues
        cur.execute("SELECT issue_id FROM issues WHERE duplicate_of_issue_id = %s", (issue_id,))
        referencing = cur.fetchall()
        if referencing:
            ref_ids = ", ".join(r["issue_id"] for r in referencing)
            return jsonify({
                "success": False,
                "error": "Cannot delete issue",
                "message": f"Cannot delete issue {issue_id}: referenced by duplicates ({ref_ids})."
            }), 400

        cur.execute("DELETE FROM issues WHERE issue_id = %s", (issue_id,))
        conn.commit()

    return jsonify({
        "success": True,
        "message": f"Issue '{issue_id}' deleted successfully."
    }), 200


# 6. PATCH /api/issues/<issue_id>/assign
@app.route("/api/issues/<issue_id>/assign", methods=["PATCH"])
@api_login_required
def api_issue_assign(user, issue_id):
    """Assign an issue to a valid active user with project scope check."""
    if user["role"] not in ["ADMIN", "PROJECT_MANAGER"]:
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "Only administrators and project managers can assign issues."
        }), 403

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "assigned_to" not in data:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": "assigned_to field is required in JSON payload."
        }), 400

    unexpected = set(data.keys()) - {"assigned_to", "csrf_token"}
    if unexpected:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": f"Unexpected fields in request: {', '.join(sorted(unexpected))}."
        }), 400

    assigned_to = str(data.get("assigned_to", "")).strip()
    if not assigned_to:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": "assigned_to cannot be empty."
        }), 400

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT i.issue_id, i.assigned_to, p.project_manager_id 
            FROM issues i 
            JOIN projects p ON i.project_id = p.project_id 
            WHERE i.issue_id = %s
        """, (issue_id,))
        issue = cur.fetchone()
        if not issue:
            return jsonify({
                "success": False,
                "error": "Not Found",
                "message": f"Issue '{issue_id}' not found."
            }), 404

        if user["role"] == "PROJECT_MANAGER" and issue["project_manager_id"] != user["user_id"]:
            return jsonify({
                "success": False,
                "error": "Forbidden",
                "message": "Project managers can only assign issues within projects they manage."
            }), 403

        cur.execute("SELECT user_id, display_name, active FROM users WHERE user_id = %s", (assigned_to,))
        target_user = cur.fetchone()
        if not target_user or not target_user["active"]:
            return jsonify({
                "success": False,
                "error": "Validation Error",
                "message": f"Assigned user '{assigned_to}' is invalid or inactive."
            }), 400

        cur.execute(
            "UPDATE issues SET assigned_to = %s, updated_date = CURRENT_DATE WHERE issue_id = %s",
            (assigned_to, issue_id)
        )
        log_activity(
            cur, issue_id, user["user_id"], "ASSIGNED",
            f"Assigned to {target_user['display_name']}",
            old_value=issue["assigned_to"],
            new_value=target_user["display_name"]
        )
        conn.commit()

    return jsonify({
        "success": True,
        "message": f"Issue '{issue_id}' assigned to {target_user['display_name']}.",
        "issue_id": issue_id,
        "assigned_to": assigned_to,
        "assignee_name": target_user["display_name"]
    }), 200


# 7. PATCH /api/issues/<issue_id>/status
@app.route("/api/issues/<issue_id>/status", methods=["PATCH"])
@api_login_required
def api_issue_update_status(user, issue_id):
    """Update issue lifecycle status enforcing Milestone 2 sequential transitions."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "status" not in data:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": "status field is required in JSON payload."
        }), 400

    unexpected = set(data.keys()) - {"status", "resolution_summary", "csrf_token"}
    if unexpected:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": f"Unexpected fields in request: {', '.join(sorted(unexpected))}."
        }), 400

    new_status = str(data.get("status", "")).strip()
    if not new_status:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": "status cannot be empty."
        }), 400

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT i.issue_id, i.status, i.assigned_to, i.created_by, i.project_id, p.project_manager_id
            FROM issues i
            JOIN projects p ON i.project_id = p.project_id
            WHERE i.issue_id = %s
        """, (issue_id,))
        issue = cur.fetchone()

        if not issue:
            return jsonify({
                "success": False,
                "error": "Not Found",
                "message": f"Issue '{issue_id}' not found."
            }), 404

        role = user["role"]
        user_id = user["user_id"]
        can_update = (
            role == "ADMIN" or
            (role == "PROJECT_MANAGER" and issue["project_manager_id"] == user_id) or
            (role == "DEVELOPER" and issue["assigned_to"] == user_id) or
            (role == "TESTER")
        )
        if not can_update:
            return jsonify({
                "success": False,
                "error": "Forbidden",
                "message": "You do not have permission to change the status of this issue."
            }), 403

        old_status = issue["status"]
        allowed = WORKFLOW_TRANSITIONS.get(old_status, [])
        if new_status not in allowed:
            return jsonify({
                "success": False,
                "error": "Invalid workflow transition",
                "message": f"Cannot move from '{old_status}' to '{new_status}'. Permitted next status: {', '.join(allowed) or 'None (terminal)'}.",
                "current_status": old_status,
                "allowed_transitions": allowed
            }), 400

        resolution_summary = data.get("resolution_summary")
        if new_status == "Resolved" and resolution_summary:
            cur.execute("""
                UPDATE issues 
                SET status = %s, resolution_summary = %s, updated_date = CURRENT_DATE 
                WHERE issue_id = %s
            """, (new_status, resolution_summary, issue_id))
        else:
            cur.execute("""
                UPDATE issues 
                SET status = %s, updated_date = CURRENT_DATE 
                WHERE issue_id = %s
            """, (new_status, issue_id))

        log_activity(
            cur, issue_id, user["user_id"], "STATUS_CHANGE",
            f"Status changed from {old_status} to {new_status}",
            old_value=old_status,
            new_value=new_status
        )
        conn.commit()

    return jsonify({
        "success": True,
        "message": f"Status updated from '{old_status}' to '{new_status}'.",
        "issue_id": issue_id,
        "old_status": old_status,
        "new_status": new_status
    }), 200


# 8. GET /api/projects/<project_id>/issues
@app.route("/api/projects/<project_id>/issues", methods=["GET"])
@api_login_required
def api_project_issues(user, project_id):
    """Retrieve issues belonging to a specific project with optional filtering."""
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT project_id, project_name FROM projects WHERE project_id = %s", (project_id,))
        project = cur.fetchone()
        if not project:
            return jsonify({
                "success": False,
                "error": "Not Found",
                "message": f"Project '{project_id}' not found."
            }), 404

        status = request.args.get("status")
        priority = request.args.get("priority")
        severity = request.args.get("severity")

        query_parts = ["""
            SELECT i.*, p.project_name, 
                   u_assigned.display_name AS assignee_name,
                   u_created.display_name AS creator_name
            FROM issues i
            JOIN projects p ON i.project_id = p.project_id
            LEFT JOIN users u_assigned ON i.assigned_to = u_assigned.user_id
            LEFT JOIN users u_created ON i.created_by = u_created.user_id
            WHERE i.project_id = %s
        """]
        params = [project_id]

        if status:
            query_parts.append("AND i.status = %s")
            params.append(status)
        if priority:
            query_parts.append("AND i.priority = %s")
            params.append(priority)
        if severity:
            query_parts.append("AND i.severity = %s")
            params.append(severity)

        query_parts.append("ORDER BY i.created_date DESC, i.issue_id DESC")
        cur.execute(" ".join(query_parts), params)
        issues = cur.fetchall()

    return jsonify({
        "success": True,
        "project_id": project_id,
        "project_name": project["project_name"],
        "count": len(issues),
        "issues": [serialize_issue(r) for r in issues]
    }), 200


# ---------------------------------------------------------------------------
# Milestone 3: Module 2 — GitHub Webhook Integration
# ---------------------------------------------------------------------------
@app.route("/webhooks/github", methods=["POST"])
def github_webhook():
    """Receives and verifies GitHub push webhook events, linking commits to issues."""
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        return jsonify({
            "success": False,
            "error": "Configuration Error",
            "message": "GITHUB_WEBHOOK_SECRET is not configured on the server."
        }), 500

    signature_header = request.headers.get("X-Hub-Signature-256", "")
    if not signature_header or not signature_header.startswith("sha256="):
        return jsonify({
            "success": False,
            "error": "Unauthorized",
            "message": "Missing or malformed X-Hub-Signature-256 header."
        }), 401

    received_sig = signature_header[7:]
    payload_bytes = request.get_data()

    computed_sig = hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()

    if not secrets.compare_digest(computed_sig, received_sig):
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "HMAC signature verification failed."
        }), 403

    event_type = request.headers.get("X-GitHub-Event", "push")
    if event_type != "push":
        return jsonify({
            "success": True,
            "status": "ignored",
            "message": f"Event '{event_type}' ignored. Only 'push' events are supported."
        }), 200

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({
            "success": False,
            "error": "Bad Request",
            "message": "Invalid JSON payload."
        }), 400

    repo = payload.get("repository", {})
    repo_name = repo.get("full_name") or repo.get("name")
    repo_url = repo.get("html_url")
    commits_list = payload.get("commits", [])

    conn = get_db()
    linked_count = 0
    processed_count = 0

    with conn.cursor() as cur:
        for c in commits_list:
            if not isinstance(c, dict):
                continue
            commit_sha = c.get("id") or c.get("sha")
            commit_msg = c.get("message", "")
            if not commit_sha or not commit_msg:
                continue

            processed_count += 1

            # Extract candidate issue IDs from message: e.g. BUG-00001, BUG-00750
            candidate_ids = re.findall(r"\b(BUG-\d+)\b", commit_msg, re.IGNORECASE)
            if not candidate_ids:
                continue

            # Associate with the first valid existing issue ID in the database
            matched_issue_id = None
            for cid in candidate_ids:
                formatted_cid = cid.upper()
                cur.execute("SELECT issue_id FROM issues WHERE issue_id = %s", (formatted_cid,))
                if cur.fetchone():
                    matched_issue_id = formatted_cid
                    break

            if not matched_issue_id:
                continue

            # Extract author
            author_obj = c.get("author")
            if isinstance(author_obj, dict):
                commit_author = author_obj.get("name") or author_obj.get("email") or "Unknown"
            else:
                commit_author = str(author_obj) if author_obj else "Unknown"

            # Direct commit URL
            direct_url = c.get("url")
            if repo_url and (not direct_url or "api.github.com" in direct_url):
                commit_url = f"{repo_url.rstrip('/')}/commit/{commit_sha}"
            else:
                commit_url = direct_url or (f"{repo_url.rstrip('/')}/commit/{commit_sha}" if repo_url else None)

            # Committed timestamp
            committed_at = c.get("timestamp") or datetime.datetime.now(datetime.timezone.utc)

            # Insert commit idempotently using UNIQUE constraint on commit_sha
            cur.execute("""
                INSERT INTO commits (
                    commit_sha, issue_id, commit_message, commit_author,
                    repository_name, repository_url, committed_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (commit_sha) DO NOTHING
                RETURNING commit_id;
            """, (
                commit_sha, matched_issue_id, commit_msg, commit_author,
                repo_name, commit_url, committed_at
            ))
            if cur.fetchone():
                linked_count += 1

        conn.commit()

    return jsonify({
        "success": True,
        "message": "GitHub push webhook processed successfully.",
        "processed_commits": processed_count,
        "linked_commits": linked_count
    }), 200


# ===========================================================================
# Milestone 3 - Module 3: Project Analytics Engine
# ===========================================================================

@app.route("/api/analytics/overview", methods=["GET"])
@api_login_required
def api_analytics_overview(user):
    """Retrieve system-wide or project-scoped issue summary, resolution time, and defect density."""
    project_id = request.args.get("project_id")
    conn = get_db()
    with conn.cursor() as cur:
        if project_id:
            cur.execute("SELECT project_id, project_name, project_manager_id FROM projects WHERE project_id = %s", (project_id,))
            proj = cur.fetchone()
            if not proj:
                return jsonify({
                    "success": False,
                    "error": "Not Found",
                    "message": f"Project '{project_id}' not found."
                }), 404
            if user["role"] == "PROJECT_MANAGER" and proj["project_manager_id"] != user["user_id"]:
                return jsonify({
                    "success": False,
                    "error": "Forbidden",
                    "message": f"Project Manager is not authorized to access analytics for unmanaged project '{project_id}'."
                }), 403
            scope_filter = "WHERE i.project_id = %s"
            params = [project_id]
        elif user["role"] == "PROJECT_MANAGER":
            scope_filter = "WHERE i.project_id IN (SELECT project_id FROM projects WHERE project_manager_id = %s)"
            params = [user["user_id"]]
        else:
            scope_filter = ""
            params = []

        cur.execute(f"""
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
            FROM issues i
            {scope_filter};
        """, params)
        counts = cur.fetchone()
        total = counts["total_issues"] or 0
        resolved_closed = (counts["resolved_issues"] or 0) + (counts["closed_issues"] or 0)
        res_pct = round((resolved_closed * 100.0) / total, 2) if total > 0 else 0.0

        cur.execute(f"""
            SELECT 
                COUNT(*) AS sample_size,
                ROUND(AVG(res.effective_hours), 2) AS avg_hours,
                ROUND(AVG(res.effective_hours) / 24.0, 2) AS avg_days
            FROM issues i
            JOIN (
                SELECT 
                    i_inner.issue_id,
                    COALESCE(
                        i_inner.resolution_time_hours,
                        EXTRACT(EPOCH FROM (h.created_at - i_inner.created_date::timestamp)) / 3600.0,
                        CASE WHEN i_inner.resolved_date IS NOT NULL AND i_inner.resolved_date >= i_inner.created_date 
                             THEN (i_inner.resolved_date - i_inner.created_date) * 24.0 ELSE NULL END
                    ) AS effective_hours
                FROM issues i_inner
                LEFT JOIN (
                    SELECT issue_id, MIN(created_at) AS created_at
                    FROM activity_history
                    WHERE new_value = 'Resolved'
                    GROUP BY issue_id
                ) h ON i_inner.issue_id = h.issue_id
                WHERE i_inner.status IN ('Resolved', 'Closed')
            ) res ON i.issue_id = res.issue_id
            {scope_filter}
            {'AND' if scope_filter else 'WHERE'} res.effective_hours IS NOT NULL AND res.effective_hours >= 0;
        """, params)
        time_row = cur.fetchone()

    response_data = {
        "success": True,
        "summary": {
            "total_issues": counts["total_issues"] or 0,
            "open_issues": counts["open_issues"] or 0,
            "in_progress_issues": counts["in_progress_issues"] or 0,
            "testing_issues": counts["testing_issues"] or 0,
            "resolved_issues": counts["resolved_issues"] or 0,
            "closed_issues": counts["closed_issues"] or 0,
            "pending_issues": counts["pending_issues"] or 0,
            "resolution_percentage": res_pct
        },
        "severity_breakdown": {
            "critical": counts["critical_issues"] or 0,
            "high": counts["high_issues"] or 0,
            "medium": counts["medium_issues"] or 0,
            "low": counts["low_issues"] or 0
        },
        "resolution_time": {
            "sample_size": time_row["sample_size"] or 0,
            "average_resolution_hours": float(time_row["avg_hours"]) if time_row["avg_hours"] is not None else 0.0,
            "average_resolution_days": float(time_row["avg_days"]) if time_row["avg_days"] is not None else 0.0
        },
        "defect_density": {
            "available": False,
            "reason": "Code-size denominator (KLOC/LOC) not present in database schema."
        }
    }
    if project_id:
        response_data["project_id"] = project_id

    return jsonify(response_data), 200


@app.route("/api/analytics/projects", methods=["GET"])
@api_login_required
def api_analytics_projects(user):
    """List analytics across all projects or only managed projects for Project Managers."""
    conn = get_db()
    with conn.cursor() as cur:
        if user["role"] == "PROJECT_MANAGER":
            where_clause = "WHERE p.project_manager_id = %s"
            params = [user["user_id"]]
        else:
            where_clause = ""
            params = []

        cur.execute(f"""
            SELECT 
                p.project_id,
                p.project_name,
                p.project_manager_id,
                p.lifecycle_status,
                COUNT(i.issue_id) AS total_issues,
                COUNT(i.issue_id) FILTER (WHERE i.status = 'Open') AS open_issues,
                COUNT(i.issue_id) FILTER (WHERE i.status = 'In Progress') AS in_progress_issues,
                COUNT(i.issue_id) FILTER (WHERE i.status = 'Testing') AS testing_issues,
                COUNT(i.issue_id) FILTER (WHERE i.status = 'Resolved') AS resolved_issues,
                COUNT(i.issue_id) FILTER (WHERE i.status = 'Closed') AS closed_issues,
                COUNT(i.issue_id) FILTER (WHERE i.status NOT IN ('Resolved', 'Closed')) AS pending_issues,
                CASE WHEN COUNT(i.issue_id) > 0 
                     THEN ROUND((COUNT(i.issue_id) FILTER (WHERE i.status IN ('Resolved', 'Closed')) * 100.0) / COUNT(i.issue_id), 2)
                     ELSE 0.00 END AS resolution_percentage,
                ROUND(AVG(res.effective_hours), 2) AS avg_resolution_hours,
                ROUND(AVG(res.effective_hours) / 24.0, 2) AS avg_resolution_days
            FROM projects p
            LEFT JOIN issues i ON p.project_id = i.project_id
            LEFT JOIN (
                SELECT 
                    i_inner.issue_id,
                    COALESCE(
                        i_inner.resolution_time_hours,
                        EXTRACT(EPOCH FROM (h.created_at - i_inner.created_date::timestamp)) / 3600.0,
                        CASE WHEN i_inner.resolved_date IS NOT NULL AND i_inner.resolved_date >= i_inner.created_date 
                             THEN (i_inner.resolved_date - i_inner.created_date) * 24.0 ELSE NULL END
                    ) AS effective_hours
                FROM issues i_inner
                LEFT JOIN (
                    SELECT issue_id, MIN(created_at) AS created_at
                    FROM activity_history
                    WHERE new_value = 'Resolved'
                    GROUP BY issue_id
                ) h ON i_inner.issue_id = h.issue_id
                WHERE i_inner.status IN ('Resolved', 'Closed')
            ) res ON i.issue_id = res.issue_id AND res.effective_hours >= 0
            {where_clause}
            GROUP BY p.project_id, p.project_name, p.project_manager_id, p.lifecycle_status
            ORDER BY p.project_id;
        """, params)
        rows = cur.fetchall()

    projects_data = []
    for r in rows:
        projects_data.append({
            "project_id": r["project_id"],
            "project_name": r["project_name"],
            "project_manager_id": r["project_manager_id"],
            "lifecycle_status": r["lifecycle_status"],
            "total_issues": r["total_issues"] or 0,
            "open_issues": r["open_issues"] or 0,
            "in_progress_issues": r["in_progress_issues"] or 0,
            "testing_issues": r["testing_issues"] or 0,
            "resolved_issues": r["resolved_issues"] or 0,
            "closed_issues": r["closed_issues"] or 0,
            "pending_issues": r["pending_issues"] or 0,
            "resolution_percentage": float(r["resolution_percentage"]) if r["resolution_percentage"] is not None else 0.0,
            "average_resolution_hours": float(r["avg_resolution_hours"]) if r["avg_resolution_hours"] is not None else 0.0,
            "average_resolution_days": float(r["avg_resolution_days"]) if r["avg_resolution_days"] is not None else 0.0
        })

    return jsonify({
        "success": True,
        "count": len(projects_data),
        "projects": projects_data
    }), 200


@app.route("/api/analytics/projects/<project_id>", methods=["GET"])
@api_login_required
def api_analytics_project_detail(user, project_id):
    """Retrieve detailed analytics for a single project including module and severity breakdowns."""
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM projects WHERE project_id = %s", (project_id,))
        proj = cur.fetchone()
        if not proj:
            return jsonify({
                "success": False,
                "error": "Not Found",
                "message": f"Project '{project_id}' not found."
            }), 404

        if user["role"] == "PROJECT_MANAGER" and proj["project_manager_id"] != user["user_id"]:
            return jsonify({
                "success": False,
                "error": "Forbidden",
                "message": f"Project Manager is not authorized to access analytics for unmanaged project '{project_id}'."
            }), 403

        # Issue summary
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
            FROM issues
            WHERE project_id = %s;
        """, (project_id,))
        summary_row = cur.fetchone()
        total = summary_row["total_issues"] or 0
        resolved_closed = (summary_row["resolved_issues"] or 0) + (summary_row["closed_issues"] or 0)
        res_pct = round((resolved_closed * 100.0) / total, 2) if total > 0 else 0.0

        # Average resolution time
        cur.execute("""
            SELECT 
                COUNT(*) AS sample_size,
                ROUND(AVG(res.effective_hours), 2) AS avg_hours,
                ROUND(AVG(res.effective_hours) / 24.0, 2) AS avg_days
            FROM issues i
            JOIN (
                SELECT 
                    i_inner.issue_id,
                    COALESCE(
                        i_inner.resolution_time_hours,
                        EXTRACT(EPOCH FROM (h.created_at - i_inner.created_date::timestamp)) / 3600.0,
                        CASE WHEN i_inner.resolved_date IS NOT NULL AND i_inner.resolved_date >= i_inner.created_date 
                             THEN (i_inner.resolved_date - i_inner.created_date) * 24.0 ELSE NULL END
                    ) AS effective_hours
                FROM issues i_inner
                LEFT JOIN (
                    SELECT issue_id, MIN(created_at) AS created_at
                    FROM activity_history
                    WHERE new_value = 'Resolved'
                    GROUP BY issue_id
                ) h ON i_inner.issue_id = h.issue_id
                WHERE i_inner.status IN ('Resolved', 'Closed')
            ) res ON i.issue_id = res.issue_id
            WHERE i.project_id = %s AND res.effective_hours >= 0;
        """, (project_id,))
        time_row = cur.fetchone()

        # Module breakdown for this project
        cur.execute("""
            SELECT 
                COALESCE(NULLIF(TRIM(component), ''), 'Unassigned') AS module_name,
                COUNT(*) AS total_defects,
                COUNT(*) FILTER (WHERE status = 'Open') AS open_defects,
                COUNT(*) FILTER (WHERE status = 'In Progress') AS in_progress_defects,
                COUNT(*) FILTER (WHERE status = 'Testing') AS testing_defects,
                COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved_defects,
                COUNT(*) FILTER (WHERE status = 'Closed') AS closed_defects,
                COUNT(*) FILTER (WHERE status NOT IN ('Resolved', 'Closed')) AS pending_defects,
                COUNT(*) FILTER (WHERE severity = 'Critical') AS critical_count,
                COUNT(*) FILTER (WHERE severity = 'High') AS high_count,
                COUNT(*) FILTER (WHERE severity = 'Medium') AS medium_count,
                COUNT(*) FILTER (WHERE severity = 'Low') AS low_count
            FROM issues
            WHERE project_id = %s
            GROUP BY 1
            ORDER BY total_defects DESC, module_name;
        """, (project_id,))
        module_rows = cur.fetchall()

    modules_data = []
    for m in module_rows:
        modules_data.append({
            "module_name": m["module_name"],
            "total_defects": m["total_defects"],
            "open_defects": m["open_defects"],
            "in_progress_defects": m["in_progress_defects"],
            "testing_defects": m["testing_defects"],
            "resolved_defects": m["resolved_defects"],
            "closed_defects": m["closed_defects"],
            "pending_defects": m["pending_defects"],
            "severity_breakdown": {
                "critical": m["critical_count"],
                "high": m["high_count"],
                "medium": m["medium_count"],
                "low": m["low_count"]
            }
        })

    return jsonify({
        "success": True,
        "project": {
            "project_id": proj["project_id"],
            "project_name": proj["project_name"],
            "description": proj["description"],
            "project_manager_id": proj["project_manager_id"],
            "lifecycle_status": proj["lifecycle_status"],
            "total_issues": total,
            "open_issues": summary_row["open_issues"] or 0,
            "in_progress_issues": summary_row["in_progress_issues"] or 0,
            "testing_issues": summary_row["testing_issues"] or 0,
            "resolved_issues": summary_row["resolved_issues"] or 0,
            "closed_issues": summary_row["closed_issues"] or 0,
            "pending_issues": summary_row["pending_issues"] or 0,
            "resolution_percentage": res_pct
        },
        "resolution_time": {
            "sample_size": time_row["sample_size"] or 0,
            "average_resolution_hours": float(time_row["avg_hours"]) if time_row["avg_hours"] is not None else 0.0,
            "average_resolution_days": float(time_row["avg_days"]) if time_row["avg_days"] is not None else 0.0
        },
        "severity_breakdown": {
            "critical": summary_row["critical_issues"] or 0,
            "high": summary_row["high_issues"] or 0,
            "medium": summary_row["medium_issues"] or 0,
            "low": summary_row["low_issues"] or 0
        },
        "modules": modules_data
    }), 200


@app.route("/api/analytics/trends", methods=["GET"])
@api_login_required
def api_analytics_trends(user):
    """Track monthly newly reported defects and resolved defects."""
    project_id = request.args.get("project_id")
    conn = get_db()
    with conn.cursor() as cur:
        if project_id:
            cur.execute("SELECT project_id, project_manager_id FROM projects WHERE project_id = %s", (project_id,))
            proj = cur.fetchone()
            if not proj:
                return jsonify({
                    "success": False,
                    "error": "Not Found",
                    "message": f"Project '{project_id}' not found."
                }), 404
            if user["role"] == "PROJECT_MANAGER" and proj["project_manager_id"] != user["user_id"]:
                return jsonify({
                    "success": False,
                    "error": "Forbidden",
                    "message": f"Project Manager is not authorized to access analytics for unmanaged project '{project_id}'."
                }), 403
            scope_filter = "WHERE i.project_id = %s"
            params = [project_id]
        elif user["role"] == "PROJECT_MANAGER":
            scope_filter = "WHERE i.project_id IN (SELECT project_id FROM projects WHERE project_manager_id = %s)"
            params = [user["user_id"]]
        else:
            scope_filter = ""
            params = []

        cur.execute(f"""
            SELECT TO_CHAR(DATE_TRUNC('month', created_date), 'YYYY-MM') AS month, COUNT(*) AS reported_count
            FROM issues i
            {scope_filter}
            {'AND' if scope_filter else 'WHERE'} created_date IS NOT NULL
            GROUP BY 1
            ORDER BY 1;
        """, params)
        reported_rows = cur.fetchall()

        cur.execute(f"""
            SELECT TO_CHAR(DATE_TRUNC('month', COALESCE(h.created_at::date, i.resolved_date, i.updated_date)), 'YYYY-MM') AS month, COUNT(*) AS resolved_count
            FROM issues i
            LEFT JOIN (
                SELECT issue_id, MIN(created_at) AS created_at
                FROM activity_history
                WHERE new_value = 'Resolved'
                GROUP BY issue_id
            ) h ON i.issue_id = h.issue_id
            {scope_filter}
            {'AND' if scope_filter else 'WHERE'} i.status IN ('Resolved', 'Closed')
              AND COALESCE(h.created_at::date, i.resolved_date, i.updated_date) IS NOT NULL
            GROUP BY 1
            ORDER BY 1;
        """, params)
        resolved_rows = cur.fetchall()

    reported_map = {r["month"]: r["reported_count"] for r in reported_rows if r["month"]}
    resolved_map = {r["month"]: r["resolved_count"] for r in resolved_rows if r["month"]}
    all_months = sorted(set(list(reported_map.keys()) + list(resolved_map.keys())))

    trends = [
        {
            "month": m,
            "reported_count": reported_map.get(m, 0),
            "resolved_count": resolved_map.get(m, 0)
        }
        for m in all_months
    ]

    return jsonify({
        "success": True,
        "count": len(trends),
        "trends": trends
    }), 200


@app.route("/api/analytics/modules", methods=["GET"])
@api_login_required
def api_analytics_modules(user):
    """Group defects by component / module with status and severity distributions."""
    project_id = request.args.get("project_id")
    conn = get_db()
    with conn.cursor() as cur:
        if project_id:
            cur.execute("SELECT project_id, project_manager_id FROM projects WHERE project_id = %s", (project_id,))
            proj = cur.fetchone()
            if not proj:
                return jsonify({
                    "success": False,
                    "error": "Not Found",
                    "message": f"Project '{project_id}' not found."
                }), 404
            if user["role"] == "PROJECT_MANAGER" and proj["project_manager_id"] != user["user_id"]:
                return jsonify({
                    "success": False,
                    "error": "Forbidden",
                    "message": f"Project Manager is not authorized to access analytics for unmanaged project '{project_id}'."
                }), 403
            scope_filter = "WHERE i.project_id = %s"
            params = [project_id]
        elif user["role"] == "PROJECT_MANAGER":
            scope_filter = "WHERE i.project_id IN (SELECT project_id FROM projects WHERE project_manager_id = %s)"
            params = [user["user_id"]]
        else:
            scope_filter = ""
            params = []

        cur.execute(f"""
            SELECT 
                COALESCE(NULLIF(TRIM(component), ''), 'Unassigned') AS module_name,
                COUNT(*) AS total_defects,
                COUNT(*) FILTER (WHERE status = 'Open') AS open_defects,
                COUNT(*) FILTER (WHERE status = 'In Progress') AS in_progress_defects,
                COUNT(*) FILTER (WHERE status = 'Testing') AS testing_defects,
                COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved_defects,
                COUNT(*) FILTER (WHERE status = 'Closed') AS closed_defects,
                COUNT(*) FILTER (WHERE status NOT IN ('Resolved', 'Closed')) AS pending_defects,
                COUNT(*) FILTER (WHERE severity = 'Critical') AS critical_count,
                COUNT(*) FILTER (WHERE severity = 'High') AS high_count,
                COUNT(*) FILTER (WHERE severity = 'Medium') AS medium_count,
                COUNT(*) FILTER (WHERE severity = 'Low') AS low_count
            FROM issues i
            {scope_filter}
            GROUP BY 1
            ORDER BY total_defects DESC, module_name;
        """, params)
        rows = cur.fetchall()

    modules_data = []
    for m in rows:
        modules_data.append({
            "module_name": m["module_name"],
            "total_defects": m["total_defects"],
            "open_defects": m["open_defects"],
            "in_progress_defects": m["in_progress_defects"],
            "testing_defects": m["testing_defects"],
            "resolved_defects": m["resolved_defects"],
            "closed_defects": m["closed_defects"],
            "pending_defects": m["pending_defects"],
            "severity_breakdown": {
                "critical": m["critical_count"],
                "high": m["high_count"],
                "medium": m["medium_count"],
                "low": m["low_count"]
            }
        })

    return jsonify({
        "success": True,
        "count": len(modules_data),
        "modules": modules_data
    }), 200


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
