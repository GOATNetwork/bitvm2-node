CREATE TABLE IF NOT EXISTS p2p_inbox (
    message_id TEXT NOT NULL PRIMARY KEY,
    business_id TEXT,
    actor TEXT NOT NULL,
    from_peer TEXT NOT NULL,
    msg_type TEXT NOT NULL,
    content BLOB NOT NULL,
    content_size BIGINT NOT NULL,
    state TEXT NOT NULL DEFAULT 'Pending',
    attempt_count BIGINT NOT NULL DEFAULT 0,
    next_retry_at BIGINT NOT NULL DEFAULT 0,
    lease_until BIGINT NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_p2p_inbox_ready
    ON p2p_inbox (state, next_retry_at, created_at);
