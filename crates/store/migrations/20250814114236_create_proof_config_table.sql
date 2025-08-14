-- Add migration script here
DROP TABLE IF EXISTS `proof_config`;
CREATE TABLE proof_config
(
    `id`                      INT    NOT NULL DEFAULT 1,
    `block_proof_concurrency` INT    NOT NULL DEFAULT 1,
    `updated_at`              BIGINT NOT NULL DEFAULT 0,
    aggregate_block_count     INT    NOT NULL DEFAULT 1,
    start_aggregation_number  INT    NOT NULL DEFAULT 2,
    PRIMARY KEY (`id`)
);