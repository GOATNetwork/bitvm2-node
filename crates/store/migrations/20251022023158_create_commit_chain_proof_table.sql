-- Add migration script here
DROP TABLE IF EXISTS `commit_chain_proof`;
CREATE TABLE commit_chain_proof
(
    `id`                  INTEGER PRIMARY KEY AUTOINCREMENT,
    `commits_info`        TEXT,
    `pre_proof_file_path` TEXT,
    `proof_file_path`     TEXT   NOT NULL,
    `status`              TEXT   NOT NULL CHECK (status IN ('queued', 'executed', 'proved', 'failed')),
    `proving_time`        BIGINT NOT NULL DEFAULT 0,
    `created_at`          BIGINT NOT NULL DEFAULT 0,
    `updated_at`          BIGINT NOT NULL DEFAULT 0,
);