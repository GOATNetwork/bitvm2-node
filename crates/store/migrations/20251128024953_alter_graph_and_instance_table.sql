-- Add migration script here
ALTER TABLE `instance`
    ADD COLUMN `status_updated_at` BIGINT NOT NULL DEFAULT 0;

ALTER TABLE `graph`
    ADD COLUMN `status_updated_at` BIGINT NOT NULL DEFAULT 0;