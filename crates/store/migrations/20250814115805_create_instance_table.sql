-- Add migration script here
DROP TABLE IF EXISTS `instance`;
CREATE TABLE instance
(
    `instance_id`             TEXT            NOT NULL DEFAULT '',
    `network`                 TEXT            NOT NULL DEFAULT 'test',
    `from_addr`               TEXT            NOT NULL DEFAULT '',
    `to_addr`                 TEXT            NOT NULL DEFAULT '',
    `amount`                  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `fees`                    TEXT            NOT NULL DEFAULT '[0, 0, 0]',
    `status`                  TEXT            NOT NULL DEFAULT '',
    `pegin_request_txid`      TEXT            NOT NULL DEFAULT '',
    `pegin_request_height`    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `user_xonly_pubkey`       TEXT            NOT NULL DEFAULT '[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]',
    `user_change_addr`        TEXT            NOT NULL DEFAULT '',
    `user_refund_addr`        TEXT            NOT NULL DEFAULT '',
    `pegin_prepare_txid`      TEXT,
    `pegin_confirm_txid`      TEXT,
    `pegin_cancel_txid`       TEXT,
    `unsign_pegin_confirm_tx` TEXT,
    `committees_answers`      TEXT            NOT NULL DEFAULT '{}',
    `pegin_data_txid`         TEXT            NOT NULL DEFAULT '',
    `timeout`                 BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `created_at`              BIGINT          NOT NULL DEFAULT 0,
    `updated_at`              BIGINT          NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`)
);