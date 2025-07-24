-- Add migration script here
ALTER TABLE groth16_proof
    ADD COLUMN start_number INT NOT NULL DEFAULT 0;
ALTER TABLE groth16_proof
    ADD COLUMN real_numbers TEXT NOT NULL DEFAULT '';
