-- Add migration script here
ALTER TABLE `instance`
    ADD COLUMN `bridge_out_lock_time` BIGINT NOT NULL DEFAULT 0;
