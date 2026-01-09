-- Add migration script here
ALTER TABLE `instance`
    ADD COLUMN `bridge_out_amount` TEXT NOT NULL DEFAULT '0';

