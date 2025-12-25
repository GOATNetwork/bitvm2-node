-- Add migration script here
ALTER TABLE `instance`
    ADD COLUMN `post_pegin_txhash` TEXT;
