-- Database Migration for Enhanced Workflow Features
-- Run this script to add the required tables for collaboration features

-- Enhanced notifications table with collaboration support
CREATE TABLE IF NOT EXISTS workflow_notifications (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL,
    from_user_id TEXT,
    to_user_id TEXT,
    notification_type TEXT NOT NULL CHECK (notification_type IN ('assignment', 'clarification_request', 'clarification_response', 'progress_update', 'status_change', 'review_complete')),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata TEXT, -- JSON data for rich notifications
    read_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
    FOREIGN KEY (from_user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (to_user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Collaboration comments and discussions
CREATE TABLE IF NOT EXISTS collaboration_comments (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL,
    question_id TEXT,
    user_id TEXT NOT NULL,
    comment TEXT NOT NULL,
    parent_comment_id TEXT,
    is_internal BOOLEAN DEFAULT FALSE, -- Internal analyst notes vs user-visible comments
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (parent_comment_id) REFERENCES collaboration_comments (id) ON DELETE CASCADE
);

-- Progress tracking with milestones
CREATE TABLE IF NOT EXISTS review_progress (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL,
    review_id TEXT NOT NULL,
    milestone TEXT NOT NULL,
    progress_percentage INTEGER DEFAULT 0 CHECK (progress_percentage >= 0 AND progress_percentage <= 100),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
    FOREIGN KEY (review_id) REFERENCES security_reviews (id) ON DELETE CASCADE
);

-- Clarification requests and responses
CREATE TABLE IF NOT EXISTS clarification_requests (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL,
    question_id TEXT NOT NULL,
    analyst_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    request_message TEXT NOT NULL,
    response_message TEXT,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'responded', 'resolved')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    responded_at TIMESTAMP,
    FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
    FOREIGN KEY (analyst_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Analyst assignments and workload tracking
CREATE TABLE IF NOT EXISTS analyst_assignments (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL,
    analyst_id TEXT NOT NULL,
    assigned_by TEXT, -- admin who assigned (if manual)
    assignment_type TEXT DEFAULT 'automatic' CHECK (assignment_type IN ('automatic', 'manual')),
    priority INTEGER DEFAULT 1 CHECK (priority >= 1 AND priority <= 5),
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
    FOREIGN KEY (analyst_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by) REFERENCES users (id) ON DELETE SET NULL
);

-- Real-time activity feed
CREATE TABLE IF NOT EXISTS activity_feed (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    activity_type TEXT NOT NULL,
    activity_data TEXT, -- JSON data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_workflow_notifications_app_id ON workflow_notifications(application_id);
CREATE INDEX IF NOT EXISTS idx_workflow_notifications_user_id ON workflow_notifications(to_user_id);
CREATE INDEX IF NOT EXISTS idx_workflow_notifications_type ON workflow_notifications(notification_type);
CREATE INDEX IF NOT EXISTS idx_workflow_notifications_read ON workflow_notifications(read_at);

CREATE INDEX IF NOT EXISTS idx_collaboration_comments_app_id ON collaboration_comments(application_id);
CREATE INDEX IF NOT EXISTS idx_collaboration_comments_question_id ON collaboration_comments(question_id);
CREATE INDEX IF NOT EXISTS idx_collaboration_comments_user_id ON collaboration_comments(user_id);

CREATE INDEX IF NOT EXISTS idx_review_progress_app_id ON review_progress(application_id);
CREATE INDEX IF NOT EXISTS idx_review_progress_review_id ON review_progress(review_id);

CREATE INDEX IF NOT EXISTS idx_clarification_requests_app_id ON clarification_requests(application_id);
CREATE INDEX IF NOT EXISTS idx_clarification_requests_status ON clarification_requests(status);

CREATE INDEX IF NOT EXISTS idx_analyst_assignments_analyst_id ON analyst_assignments(analyst_id);
CREATE INDEX IF NOT EXISTS idx_analyst_assignments_app_id ON analyst_assignments(application_id);

CREATE INDEX IF NOT EXISTS idx_activity_feed_app_id ON activity_feed(application_id);
CREATE INDEX IF NOT EXISTS idx_activity_feed_user_id ON activity_feed(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_feed_created_at ON activity_feed(created_at);

-- Update existing notifications table to support new features
-- Note: Using try/catch approach for older SQLite versions
-- These will be handled in the Python migration script

-- Create views for common queries
CREATE VIEW IF NOT EXISTS analyst_workload AS
SELECT 
    u.id as analyst_id,
    u.first_name,
    u.last_name,
    COUNT(aa.id) as active_assignments,
    COUNT(CASE WHEN aa.started_at IS NOT NULL AND aa.completed_at IS NULL THEN 1 END) as in_progress_reviews,
    u.max_concurrent_reviews,
    u.is_available
FROM users u
LEFT JOIN analyst_assignments aa ON u.id = aa.analyst_id 
    AND aa.completed_at IS NULL
WHERE u.role = 'security_analyst' AND u.is_active = 1
GROUP BY u.id, u.first_name, u.last_name, u.max_concurrent_reviews, u.is_available;

CREATE VIEW IF NOT EXISTS application_collaboration_summary AS
SELECT 
    a.id as application_id,
    a.name as application_name,
    a.status,
    COUNT(DISTINCT wn.id) as notification_count,
    COUNT(DISTINCT cc.id) as comment_count,
    COUNT(DISTINCT cr.id) as clarification_count,
    MAX(a.last_activity_at) as last_activity
FROM applications a
LEFT JOIN workflow_notifications wn ON a.id = wn.application_id
LEFT JOIN collaboration_comments cc ON a.id = cc.application_id
LEFT JOIN clarification_requests cr ON a.id = cr.application_id
GROUP BY a.id, a.name, a.status;
