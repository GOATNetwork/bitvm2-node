-- Add migration script here
DROP TABLE IF EXISTS `message_broadcast`;
CREATE TABLE message_broadcast
(
    `instance_id` TEXT   NOT NULL,
    `graph_id`    TEXT,
    `msg_type`    TEXT   NOT NULL DEFAULT '',
    `msg_times`   BIGINT NOT NULL DEFAULT 0,
    `created_at`  BIGINT NOT NULL DEFAULT 0,
    `updated_at`  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`, `graph_id`, `msg_type`),
    FOREIGN KEY (instance_id) REFERENCES instance (instance_id) ON DELETE CASCADE
        ON UPDATE CASCADE,
    FOREIGN KEY (graph_id) REFERENCES graph (graph_id) ON DELETE CASCADE
        ON UPDATE CASCADE

);
