-- Add migration script here
DROP TABLE IF EXISTS `bridge_out_global_stats`;
CREATE TABLE bridge_out_global_stats
(
    `id`             INTEGER PRIMARY KEY,
    `initial_txn`    BIGINT NOT NULL DEFAULT 0,
    `initial_amount` TEXT   NOT NULL DEFAULT '0',
    `claim_txn`      BIGINT NOT NULL DEFAULT 0,
    `claim_amount`   TEXT   NOT NULL DEFAULT '0',
    `refund_txn`     BIGINT NOT NULL DEFAULT 0,
    `refund_amount`  TEXT   NOT NULL DEFAULT '0',
    `created_at`     BIGINT NOT NULL DEFAULT 0,
    `updated_at`     BIGINT NOT NULL DEFAULT 0
);