-- Add migration script here
DROP TABLE IF EXISTS `watch_contract`;
CREATE TABLE watch_contract
(
    `contract_addr` TEXT   NOT NULL DEFAULT '',
    `gap`           BIGINT NOT NULL DEFAULT 0,
    `from_height`   BIGINT NOT NULL DEFAULT 0,
    `the_graph_url` TEXT   NOT NULL DEFAULT '',
    `status`        TEXT   NOT NULL DEFAULT 'UnSync',
    `extra`         TEXT,
    `updated_at`    BIGINT NOT NULL DEFAULT 0,
    `created_at`    BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`contract_addr`)
);