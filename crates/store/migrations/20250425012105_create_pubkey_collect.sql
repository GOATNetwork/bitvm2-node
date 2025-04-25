-- Add migration script here
DROP TABLE IF EXISTS `pubkey_collect`;
CREATE TABLE pubkey_collect
(
    `instance_id` TEXT   NOT NULL,
    `pubkeys`     TEXT   NOT NULL DEFAULT '',
    `created_at`  BIGINT NOT NULL DEFAULT 0,
    `updated_at`  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (`instance_id`),
    FOREIGN KEY (instance_id) REFERENCES instance (instance_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);
