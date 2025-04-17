-- Add migration script here
DROP TABLE IF EXISTS `node`;
CREATE TABLE node
(
    `peer_id`     TEXT NOT NULL DEFAULT '',
    `actor`       TEXT NOT NULL DEFAULT '',
    `goat_addr`   TEXT NOT NULL DEFAULT '',
    `btc_pub_key` TEXT NOT NULL DEFAULT '',
    `created_at`  BIGINT NOT NULL DEFAULT 0,
    `updated_at`  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`peer_id`)
);