-- Add migration script here
DROP TABLE IF EXISTS `node`;
CREATE TABLE node
(
    `peer_id`          TEXT   NOT NULL DEFAULT '',
    `actor`            TEXT   NOT NULL DEFAULT '',
    `goat_addr`        TEXT   NOT NULL DEFAULT '',
    `btc_pub_key`      TEXT   NOT NULL DEFAULT '',
    socket_addr        TEXT   NOT NULL DEFAULT '',
    `node_name`        TEXT   NOT NULL DEFAULT '',
    `service_fee_rate` REAL   NOT NULL DEFAULT 0.0,
    `available_peg_btc`
                       TEXT   NOT NULL DEFAULT '0',
    `reward`
                       TEXT   NOT NULL DEFAULT '0',
    `created_at`       BIGINT NOT NULL DEFAULT 0,
    `updated_at`       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`peer_id`)
);