-- Add migration script here
DROP TABLE IF EXISTS `instance`;
CREATE TABLE instance
(
    `instance_id` TEXT      NOT NULL DEFAULT '',
    `bridge_path` BOOL      NOT NULL DEFAULT -1,
    `from_addr`   TEXT      NOT NULL DEFAULT '',
    `to_addr`     TEXT      NOT NULL DEFAULT '',
    `amount`      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `status`      TEXT      NOT NULL DEFAULT '',
    `goat_txid`   TEXT      NOT NULL DEFAULT '',
    `btc_txid`    TEXT      NOT NULL DEFAULT '',
    `pegin_tx`    TEXT,
    `kickoff_tx`  TEXT,
    `created_at`  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`instance_id`)
);