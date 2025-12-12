-- Add migration script here
ALTER TABLE `instance`
    ADD COLUMN `escrow_hash` TXET;

