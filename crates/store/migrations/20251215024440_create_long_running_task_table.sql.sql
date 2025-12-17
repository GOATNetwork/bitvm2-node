-- Add migration script here
DROP TABLE IF EXISTS `long_running_task_proof`;
CREATE TABLE long_running_task_proof
(
    `id`            INTEGER PRIMARY KEY,
    `block_start`   BIGINT NOT NULL DEFAULT 0,
    `block_end`     BIGINT NOT NULL DEFAULT 0,
    `chain_name`    TEXT   NOT NULL CHECK ( chain_name in ('header-chain', 'state-chain', 'commit-chain') ),
    `path_to_proof` TEXT,
    `cycles`        BIGINT NOT NULL DEFAULT 0,
    `proof_state`   BIGINT NOT NULL DEFAULT 0 CHECK (proof_state IN (0, 1, 2, 3)),
    `proving_time`  BIGINT NOT NULL DEFAULT 0,
    `zkm_version`   TEXT   NOT NULL DEFAULT '',
    `extra`         TEXT,
    `created_at`    BIGINT NOT NULL DEFAULT 0,
    `updated_at`    BIGINT NOT NULL DEFAULT 0
);

INSERT INTO long_running_task_proof (
    block_start,
    block_end,
    chain_name,
    path_to_proof,
    cycles,
    proof_state,
    proving_time,
    zkm_version,
    extra
) VALUES (
    0,
    503050,
    'header-chain',
    '../circuits/data/header-chain/0-503050.bi',
    0,
    2,
    0,
    'v1.2.3',
    ''
);
