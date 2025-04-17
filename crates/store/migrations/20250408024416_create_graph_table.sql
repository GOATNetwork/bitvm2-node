-- Add migration script here
DROP TABLE IF EXISTS `graph`;
CREATE TABLE graph
(
    `graph_id`            TEXT            NOT NULL DEFAULT '',
    `instance_id`         TEXT            NOT NULL,
    `graph_ipfs_base_url` TEXT            NOT NULL DEFAULT '',
    `pegin_txid`          TEXT            NOT NULL DEFAULT '',
    `amount`              BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `status`              TEXT            NOT NULL DEFAULT '',
    `challenge_txid`      TEXT,
    `disprove_txid`       TEXT,
    `operator`            TEXT            NOT NULL DEFAULT '',
    `created_at`          BIGINT          NOT NULL DEFAULT 0,
    `updated_at`          BIGINT          NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`),
    FOREIGN KEY (instance_id) REFERENCES instance (instance_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);
