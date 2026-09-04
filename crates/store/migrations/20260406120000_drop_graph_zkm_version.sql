-- Drop graph-level zkm_version because version semantics now live on proofs only
ALTER TABLE graph DROP COLUMN `zkm_version`;
