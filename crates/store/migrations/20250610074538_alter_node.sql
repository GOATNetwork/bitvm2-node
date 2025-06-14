-- Add migration script here
ALTER TABLE node
    ADD COLUMN socket_addr TEXT NOT NULL DEFAULT '';
