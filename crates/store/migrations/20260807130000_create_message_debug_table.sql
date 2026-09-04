CREATE TABLE IF NOT EXISTS message_debug_reason (
    message_id TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    reason_detail TEXT NOT NULL,
    first_seen_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    occurrences BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (message_id, reason_code, reason_detail)
);
