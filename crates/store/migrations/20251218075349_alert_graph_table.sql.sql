-- Add migration script here
ALTER TABLE `graph`
    ADD COLUMN `proceed_withdraw_height` BIGINT NOT NULL DEFAULT 0;
