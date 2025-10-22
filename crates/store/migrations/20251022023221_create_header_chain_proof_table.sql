-- Add migration script here
DROP TABLE IF EXISTS `header_chain_proof`;
CREATE TABLE header_chain_proof
(
    `id`                      INTEGER PRIMARY KEY AUTOINCREMENT,
    `block_headers_file_path` TEXT,
    `pre_proof_file_path`     TEXT,
    `batch_size`              BIGINT NOT NULL DEFAULT 4,
    `start`                   BIGINT NOT NULL DEFAULT 0,
    `proof_file_path`         TEXT   NOT NULL,
    `status`                  TEXT   NOT NULL CHECK (status IN ('queued', 'executed', 'proved', 'failed')),
    `proving_time`            BIGINT NOT NULL DEFAULT 0,
    `created_at`              BIGINT NOT NULL DEFAULT 0,
    `updated_at`              BIGINT NOT NULL DEFAULT 0,
);