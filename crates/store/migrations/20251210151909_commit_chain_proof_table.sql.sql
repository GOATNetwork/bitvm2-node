-- Add migration script here
DROP TABLE IF EXISTS `commit_chain_proof`;
CREATE TABLE commit_chain_proof
(
    `id`             INTEGER PRIMARY KEY AUTOINCREMENT,
    `commits`        TEXT   NOT NULL DEFAULT '{}',
    `data_location`  TEXT   NOT NULL CHECK (status IN ('File', 'db', 'S3')),
    `proof`          TEXT   NOT NULL,
    `vk_hash`        TEXT   NOT NULL,
    `public_inputs`  TEXT   NOT NULL,
    `status`         TEXT   NOT NULL CHECK (status IN ('Pending',  'Proved', 'Failed')),
    `proving_time`   BIGINT NOT NULL DEFAULT 0,
    `proving_cycles` BIGINT NOT NULL DEFAULT 0,
    `proof_size`     BIGINT NOT NULL DEFAULT 0,
    `zkm_version`    TEXT   NOT NULL,
    `created_at`     BIGINT NOT NULL DEFAULT 0,
    `updated_at`     BIGINT NOT NULL DEFAULT 0
);
