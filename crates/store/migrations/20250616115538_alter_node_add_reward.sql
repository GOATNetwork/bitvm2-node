-- Add migration script here
ALTER TABLE node
    ADD COLUMN reward BIGINT NOT NULL DEFAULT 0;
