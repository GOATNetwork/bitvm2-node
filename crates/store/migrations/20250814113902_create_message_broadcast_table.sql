-- Add migration script here
DROP TABLE IF EXISTS `message_broadcast`;
CREATE TABLE message_broadcast
(
    `graph_id`     TEXT   NOT NULL,
    `graph_status` TEXT   NOT NuLL DEFAULT '',
    `msg_type`     TEXT   NOT NULL DEFAULT '',
    `msg_times`    BIGINT NOT NULL DEFAULT 0,
    `created_at`   BIGINT NOT NULL DEFAULT 0,
    `updated_at`   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`, `graph_status`, `msg_type`)
);