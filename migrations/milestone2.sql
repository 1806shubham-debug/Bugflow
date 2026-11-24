-- Milestone 2: Additive migrations for Comments, Attachments, and Activity History

CREATE TABLE IF NOT EXISTS comments (
    comment_id SERIAL PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    comment_text TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_comments_issue_id ON comments(issue_id);
CREATE INDEX IF NOT EXISTS idx_comments_created_at ON comments(created_at);

CREATE TABLE IF NOT EXISTS attachments (
    attachment_id SERIAL PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_attachments_issue_id ON attachments(issue_id);

CREATE TABLE IF NOT EXISTS activity_history (
    activity_id SERIAL PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    description TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_activity_history_issue_id ON activity_history(issue_id);
CREATE INDEX IF NOT EXISTS idx_activity_history_created_at ON activity_history(created_at);

CREATE INDEX IF NOT EXISTS idx_issues_sprint_id ON issues(sprint_id);

