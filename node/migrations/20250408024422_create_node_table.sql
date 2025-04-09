-- Add migration script here
DROP TABLE IF EXISTS `node`;
CREATE TABLE node
(
    `peer_id`    TEXT      NOT NULL DEFAULT '',
    `actor`      TEXT      NOT NULL DEFAULT '',
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`peer_id`)
);