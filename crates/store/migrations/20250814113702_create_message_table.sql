-- Add migration script here
DROP TABLE IF EXISTS `message`;
CREATE TABLE message
(
    `message_id`      TEXT   NOT NULL,
    `business_id`     TEXT   NOT NULL,
    `from_peer`       TEXT   NOT NULL DEFAULT 'self',
    `actor`           TEXT   NOT NULL,
    `msg_type`        TEXT   NOT NULL,
    `content`         BLOB   NOT NULL,
    `state`           TEXT   NOT NULL DEFAULT 'pending',
    `lock_time_until` BIGINT NOT NULL DEFAULT 0,
    `weight`          BIGINT NOT NULL DEFAULT 0,
    `created_at`      BIGINT NOT NULL DEFAULT 0,
    `updated_at`      BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`message_id`)
)