-- Add migration script here
DROP TABLE IF EXISTS `header_chain_proof`;
CREATE TABLE header_chain_proof
(
    `id`            INTEGER PRIMARY KEY AUTOINCREMENT,
    `in_location`   TEXT   NOT NULL CHECK (status IN ('file', 'db', 'S3')),
    `prev_proof`    TEXT,
    `batch_size`    BIGINT NOT NULL DEFAULT 4,
    `start`         BIGINT NOT NULL DEFAULT 0,
    `out_location`  TEXT   NOT NULL CHECK (status IN ('file', 'db', 'S3')),
    `proof`         TEXT   NOT NULL,
    `vk`            TEXT   NOT NULL,
    `public_inputs` TEXT   NOT NULL,
    `status`        TEXT   NOT NULL CHECK (status IN ('queued', 'executed', 'proved', 'failed')),
    `proving_time`  BIGINT NOT NULL DEFAULT 0,
    `zkm_version`   TEXT   NOT NULL,
    `created_at`    BIGINT NOT NULL DEFAULT 0,
    `updated_at`    BIGINT NOT NULL DEFAULT 0
);