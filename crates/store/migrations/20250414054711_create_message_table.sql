-- Add migration script here
DROP TABLE IF EXISTS `message`;
CREATE TABLE message
(
    `id`         INTEGER PRIMARY KEY AUTOINCREMENT,
    `from_peer`  TEXT      NOT NULL DEFAULT 'self',
    `actor`      TEXT      NOT NULL,
    `msg_type`   TEXT      NOT NULL,
    `content`    BLOB      NOT NULL,
    `state`      TEXT      NOT NULL DEFAULT 'pending',
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);