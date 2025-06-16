-- Add migration script here
ALTER TABLE groth16_proof RENAME COLUMN proof_size_b TO proof_size;
