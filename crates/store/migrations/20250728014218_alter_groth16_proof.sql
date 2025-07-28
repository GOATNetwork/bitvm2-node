-- Add migration script here
ALTER TABLE groth16_proof
    ADD COLUMN init_number INT NOT NULL DEFAULT 0;
