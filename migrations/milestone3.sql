-- Milestone 3: Additive migration for GitHub commit tracking

CREATE TABLE IF NOT EXISTS commits (
    commit_id SERIAL PRIMARY KEY,
    commit_sha TEXT NOT NULL UNIQUE,
    issue_id TEXT NOT NULL REFERENCES issues(issue_id) ON DELETE CASCADE,
    commit_message TEXT NOT NULL,
    commit_author TEXT NOT NULL,
    repository_name TEXT,
    repository_url TEXT,
    committed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_commits_issue_id ON commits(issue_id);
CREATE INDEX IF NOT EXISTS idx_commits_committed_at ON commits(committed_at);
