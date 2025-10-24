-- Add migration script here
DROP TABLE IF EXISTS `header_chain_proof`;
CREATE TABLE header_chain_proof
(
    `id`                      INTEGER PRIMARY KEY AUTOINCREMENT,
    `prev_proof_file_path`    TEXT,
    `batch_size`              BIGINT NOT NULL DEFAULT 4,
    `start`                   BIGINT NOT NULL DEFAULT 0,
    `proof_file_path`         TEXT   NOT NULL,
    `vk_file_path`            TEXT   NOT NULL,
    `public_inputs_file_path` TEXT   NOT NULL,
    `status`                  TEXT   NOT NULL CHECK (status IN ('queued', 'executed', 'proved', 'failed')),
    `proving_time`            BIGINT NOT NULL DEFAULT 0,
    `zkm_version`             TEXT   NOT NULL,
    `created_at`              BIGINT NOT NULL DEFAULT 0,
    `updated_at`              BIGINT NOT NULL DEFAULT 0
);