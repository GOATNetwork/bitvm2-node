-- Add migration script here
ALTER TABLE aggregation_proof RENAME COLUMN proof_size_mb TO proof_size;
