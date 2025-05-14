-- Add migration script here

ALTER TABLE graph
    ADD COLUMN bridge_out_start_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE graph
    ADD COLUMN bridge_out_from_addr TEXT NOT NULL DEFAULT '';
ALTER TABLE graph
    ADD COLUMN bridge_out_to_addr TEXT NOT NULL DEFAULT '';
