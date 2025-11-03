-- Add migration script here
ALTER TABLE `node`
    ADD COLUMN `node_name` TEXT NOT NULL DEFAULT '';
ALTER TABLE `node`
    ADD COLUMN `service_fee_rate` REAL NOT NULL DEFAULT 0.0;
ALTER TABLE `node`
    ADD COLUMN `available_peg_btc` BIGINT NOT NULL DEFAULT 0;
