-- Add migration script here
DROP TABLE IF EXISTS `pegin_graph_process_data`;
CREATE TABLE pegin_graph_process_data
(
    `graph_id`     TEXT    NOT NULL,
    `instance_id`  TEXT    NOT NULL,
    `process_data` TEXT    NOT NULL DEFAULT '',
    `is_endorsed`  BOOLEAN NOT NULL DEFAULT 0,
    `created_at`   BIGINT  NOT NULL DEFAULT 0,
    `updated_at`   BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`)
);
