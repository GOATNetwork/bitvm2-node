ALTER TABLE graph
    ADD COLUMN `watchtower_challenge_timeout_txids` TEXT NOT NULL DEFAULT '[]';

ALTER TABLE graph
    ADD COLUMN `operator_challenge_nack_txids` TEXT NOT NULL DEFAULT '[]';

ALTER TABLE graph
    ADD COLUMN `operator_commit_timeout_txid` TEXT;
