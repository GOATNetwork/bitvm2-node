-- Add migration script here
ALTER TABLE block_proof RENAME COLUMN proof_size_mb TO proof_size;
