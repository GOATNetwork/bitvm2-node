-- Add migration script here
-- Add migration script here
DROP TABLE IF EXISTS `graph_btc_tx_vout_monitor`;
CREATE TABLE `graph_btc_tx_vout_monitor`
(
    `graph_id`     TEXT   NOT NULL,
    `tx_name`      TEXT   NOT NULL,
    `txid`         TEXT   NOT NULL,
    `height`       BIGINT NOT NULL DEFAULT 0,
    `vout_len`     BIGINT NOT NULL DEFAULT 0,
    `monitor_data` TEXT   NOT NULL DEFAULT '',
    `created_at`   BIGINT NOT NULL DEFAULT 0,
    `updated_at`   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`, `txid`)
);
