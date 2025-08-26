-- Add migration script here
DROP TABLE IF EXISTS `goat_tx_record`;
CREATE TABLE goat_tx_record
(
    `instance_id`       TEXT   NOT NULL,
    `graph_id`          TEXT   NOT NULL,
    `tx_type`           TEXT   NOT NULL DEFAULT 'Normal',
    `tx_hash`           TEXT   NOT NULL DEFAULT '',
    `height`            BIGINT NOT NULL DEFAULT 0,
    `is_local`          BOOL   NOT NULL DEFAULT 1,
    `extra`             TEXT,
    `created_at`        BIGINT NOT NULL DEFAULT 0,
    `processing_status` TEXT   NOT NULL DEFAULT 'Skipped',
    PRIMARY KEY (`instance_id`, `graph_id`, `tx_type`)
);
CREATE INDEX id_goat_tx_hash ON goat_tx_record (`tx_hash`);