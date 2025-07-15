-- Add migration script here
DROP TABLE IF EXISTS `proof_config`;
CREATE TABLE proof_config
(
    `id`                      INT NOT NULL DEFAULT 1,
    `block_proof_concurrency` INT NOT NULL DEFAULT 1,
    `updated_at`              BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`)
);
