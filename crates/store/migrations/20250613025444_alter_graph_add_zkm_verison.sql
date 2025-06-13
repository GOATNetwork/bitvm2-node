-- Add migration script here
ALTER TABLE graph
    ADD COLUMN zkm_version TEXT NOT NULL DEFAULT '';
