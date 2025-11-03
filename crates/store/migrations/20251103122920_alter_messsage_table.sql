-- Add migration script here
ALTER TABLE `message`
    ADD COLUMN `message_version` BIGINT NOT NULL DEFAULT 0;
