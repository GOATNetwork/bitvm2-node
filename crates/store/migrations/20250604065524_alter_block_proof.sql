-- Add migration script here
ALTER TABLE block_proof
    ADD COLUMN public_values MEDIUMTEXT NOT NULL DEFAULT '';
