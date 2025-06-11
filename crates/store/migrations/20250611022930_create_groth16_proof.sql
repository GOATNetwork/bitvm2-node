-- Add migration script here
DROP TABLE IF EXISTS `groth16_proof`;
CREATE TABLE groth16_proof (
    `block_number`        BIGINT NOT NULL DEFAULT 0,
    `total_time_to_proof` BIGINT NOT NULL DEFAULT 0,
    `proving_time`        BIGINT NOT NULL DEFAULT 0,
    `proving_cycles`      BIGINT NOT NULL DEFAULT 0,
    `proof`               MEDIUMTEXT NOT NULL DEFAULT '',
    `proof_size_b`        REAL NOT NULL DEFAULT 0,
    `public_values`       MEDIUMTEXT NOT NULL DEFAULT '',
    `verifier_id`         VARCHAR(66) NOT NULL DEFAULT '',
    `zkm_version`         VARCHAR(32) NOT NULL DEFAULT '',
    `state`               VARCHAR(10) NOT NULL CHECK (state IN ('queued', 'proved', 'failed')),
    `reason`              VARCHAR(100) NOT NULL DEFAULT '',
    `created_at`          BIGINT NOT NULL DEFAULT 0,
    `updated_at`          BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`block_number`)
);
