-- Add migration script here
DROP TABLE IF EXISTS `instance`;
CREATE TABLE instance
(
    `instance_id`     TEXT            NOT NULL DEFAULT '',
    `network`         TEXT            NOT NULL DEFAULT 'test',
    `bridge_path`     BOOL            NOT NULL DEFAULT -1,
    `from_addr`       TEXT            NOT NULL DEFAULT '',
    `to_addr`         TEXT            NOT NULL DEFAULT '',
    `amount`          BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `status`          TEXT            NOT NULL DEFAULT '',
    `goat_txid`       TEXT            NOT NULL DEFAULT '',
    `btc_txid`        TEXT            NOT NULL DEFAULT '',
    `pegin_txid`      TEXT,
    `pegin_tx_height` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `kickoff_tx`      TEXT,
    `fee`             BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `input_uxtos`     TEXT            NOT NULL DEFAULT '',
    `created_at`      BIGINT          NOT NULL DEFAULT 0,
    `updated_at`      BIGINT          NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`)
);