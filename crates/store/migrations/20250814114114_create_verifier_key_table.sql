-- Add migration script here
DROP TABLE IF EXISTS `verifier_key`;
CREATE TABLE verifier_key
(
    `verifier_id`  VARCHAR(66) NOT NULL DEFAULT '',
    `verifier_key` MEDIUMTEXT  NOT NULL DEFAULT '',
    `created_at`   BIGINT      NOT NULL DEFAULT 0,
    PRIMARY KEY (`verifier_id`)
);