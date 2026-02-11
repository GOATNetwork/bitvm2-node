CREATE TABLE IF NOT EXISTS sequencer_set_hash_changes
(
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    cosmos_block_height BIGINT NOT NULL UNIQUE,
    goat_block_height   BIGINT NOT NULL,
    validators_hash     TEXT   NOT NULL,
    created_at          BIGINT NOT NULL DEFAULT 0,
    updated_at          BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sequencer_set_hash_changes_goat_block_height
    ON sequencer_set_hash_changes (goat_block_height);

CREATE TABLE IF NOT EXISTS sequencer_set_scan_state
(
    id                       INTEGER PRIMARY KEY CHECK (id = 1),
    next_cosmos_block_height BIGINT NOT NULL,
    latest_goat_block_height BIGINT NOT NULL,
    latest_validators_hash   TEXT   NOT NULL,
    created_at               BIGINT NOT NULL DEFAULT 0,
    updated_at               BIGINT NOT NULL DEFAULT 0
);
