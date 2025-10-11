-- Add migration script here
-- Add migration script here
DROP TABLE IF EXISTS `pegin_instance_process_data`;
CREATE TABLE pegin_instance_process_data
(
    `instance_id`      TEXT   NOT NULL,
    `process_data` TEXT   NOT NULL DEFAULT '',
    `created_at`       BIGINT NOT NULL DEFAULT 0,
    `updated_at`       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`)
);
