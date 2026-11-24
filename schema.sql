
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (
        role IN ('ADMIN', 'PROJECT_MANAGER', 'DEVELOPER', 'TESTER')
    ),
    active BOOLEAN NOT NULL
);

CREATE TABLE projects (
    project_id TEXT PRIMARY KEY,
    project_name TEXT NOT NULL,
    description TEXT,
    created_date DATE,
    project_manager_id TEXT REFERENCES users(user_id),
    lifecycle_status TEXT
);

CREATE TABLE workflow_states (
    state_id TEXT PRIMARY KEY,
    state_name TEXT NOT NULL UNIQUE,
    sequence INTEGER NOT NULL,
    terminal BOOLEAN NOT NULL
);

CREATE TABLE sprints (
    sprint_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    sprint_name TEXT NOT NULL,
    start_date DATE,
    end_date DATE,
    status TEXT
);

CREATE TABLE issues (
    issue_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    issue_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    priority TEXT NOT NULL,
    status TEXT NOT NULL REFERENCES workflow_states(state_name),
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    assigned_to TEXT REFERENCES users(user_id),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_date DATE,
    updated_date DATE,
    component TEXT,
    environment TEXT,
    steps_to_reproduce TEXT,
    expected_result TEXT,
    actual_result TEXT,
    business_impact TEXT,
    resolution_summary TEXT,
    root_cause TEXT,
    resolution_time_hours NUMERIC,
    resolved_date DATE,
    reopen_count INTEGER,
    is_duplicate BOOLEAN NOT NULL DEFAULT FALSE,
    duplicate_of_issue_id TEXT REFERENCES issues(issue_id),
    sprint_id TEXT REFERENCES sprints(sprint_id)
);

CREATE TABLE resolution_suggestions (
    suggestion_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id),
    rank INTEGER NOT NULL,
    suggested_action TEXT NOT NULL,
    rationale TEXT,
    confidence NUMERIC,
    source TEXT,
    accepted BOOLEAN,
    UNIQUE (issue_id, rank)
);
