CREATE TABLE IF NOT EXISTS pending_graph_init
(
    `instance_id`     TEXT   NOT NULL,
    `operator_pubkey` TEXT   NOT NULL,
    `graph_id`        TEXT   NOT NULL UNIQUE,
    `created_at`      BIGINT NOT NULL DEFAULT 0,
    `updated_at`      BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`, `operator_pubkey`)
);
