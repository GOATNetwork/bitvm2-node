-- Add migration script here
ALTER TABLE block_proof
    ADD COLUMN zkm_version VARCHAR(32) NOT NULL DEFAULT '';
