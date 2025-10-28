-- Add migration script here
DROP TABLE IF EXISTS `commit_chain_proof`;
CREATE TABLE commit_chain_proof
(
    `id`                INTEGER PRIMARY KEY AUTOINCREMENT,
    `commit_info_txids` TEXT   NOT NULL DEFAULT '[]',
    `in_location`       TEXT   NOT NULL CHECK (status IN ('file', 'db', 'S3')),
    `prev_proof`        TEXT,
    `out_location`      TEXT   NOT NULL CHECK (status IN ('file', 'db', 'S3')),
    `proof`             TEXT   NOT NULL,
    `vk`                TEXT   NOT NULL,
    `public_inputs`     TEXT   NOT NULL,
    `status`            TEXT   NOT NULL CHECK (status IN ('queued', 'executed', 'proved', 'failed')),
    `proving_time`      BIGINT NOT NULL DEFAULT 0,
    `zkm_version`       TEXT   NOT NULL,
    `created_at`        BIGINT NOT NULL DEFAULT 0,
    `updated_at`        BIGINT NOT NULL DEFAULT 0
);