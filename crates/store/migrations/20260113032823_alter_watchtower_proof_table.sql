-- Add migration script here
ALTER TABLE `watchtower_proof`
    ADD COLUMN `node_index` INTEGER NOT NULL DEFAULT 0;
ALTER TABLE `watchtower_proof`
    ADD COLUMN `included` BOOLEAN NOT NULL DEFAULT 0;