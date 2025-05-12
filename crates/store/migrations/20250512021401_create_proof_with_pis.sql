-- Add migration script here
DROP TABLE IF EXISTS `proof_with_pis`;
CREATE TABLE proof_with_pis
(
    `instance_id` TEXT   NOT NULL,
    `graph_id`    TEXT,
    `proof`    TEXT   NOT NULL DEFAULT '',
    `pis`    TEXT   NOT NULL DEFAULT '',
    `created_at`  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`, `graph_id`)
);