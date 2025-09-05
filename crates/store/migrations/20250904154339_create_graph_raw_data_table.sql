DROP TABLE IF EXISTS `graph_raw_data`;
CREATE TABLE graph_raw_data
(
    `graph_id`   TEXT   NOT NULL,
    `raw_data`   TEXT   NOT NULL DEFAULT '',
    `created_at` BIGINT NOT NULL DEFAULT 0,
    `updated_at` BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`graph_id`)
);
