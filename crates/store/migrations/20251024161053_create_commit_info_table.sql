-- Add migration script here
DROP TABLE IF EXISTS `commit_info`;
CREATE TABLE commit_info
(
    `txid`                  TEXT   NOT NULL,
    `threshold`             BIGINT NOT NULL DEFAULT 0,
    `publisher_public_keys` TEXT   NOT NULL,
    `commit_proof_id`       BIGINT NOT NULL DEFAULT 0,
    `created_at`            BIGINT NOT NULL DEFAULT 0,
    `updated_at`            BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`txid`)
);