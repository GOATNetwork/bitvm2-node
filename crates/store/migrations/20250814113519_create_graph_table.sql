-- Add migration script here
DROP TABLE IF EXISTS `graph`;
CREATE TABLE graph
(
    `graph_id`            TEXT   NOT NULL DEFAULT '',
    `instance_id`         TEXT   NOT NULL,
    `graph_ipfs_base_url` TEXT   NOT NULL DEFAULT '',
    `pegin_txid`          TEXT   NOT NULL DEFAULT '',
    `amount`              BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `status`              TEXT   NOT NULL DEFAULT '',
    `pre_kickoff_txid`    TEXT,
    `kickoff_txid`        TEXT,
    `challenge_txid`      TEXT,
    `take1_txid`          TEXT,
    `assert_init_txid`    TEXT,
    `assert_commit_txids` TEXT,
    `assert_final_txid`   TEXT,
    `take2_txid`          TEXT,
    `disprove_txid`       TEXT,
    `operator`            TEXT   NOT NULL DEFAULT '',
    `raw_data`            TEXT,
    `created_at`          BIGINT NOT NULL DEFAULT 0,
    `updated_at`          BIGINT NOT NULL DEFAULT 0,
    bridge_out_start_at   BIGINT NOT NULL DEFAULT 0,
    bridge_out_from_addr  TEXT   NOT NULL DEFAULT '',
    bridge_out_to_addr    TEXT   NOT NULL DEFAULT '',
    init_withdraw_txid    TEXT,
    zkm_version           TEXT   NOT NULL DEFAULT '',
    PRIMARY KEY (`graph_id`)
);