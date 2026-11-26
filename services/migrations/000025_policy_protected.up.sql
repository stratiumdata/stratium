-- An admin can protect a policy: an editor may then neither change nor
-- disable it. The flag is written only by PUT /v1/policies/{id}/protection
-- (admin); the policy's own create and update never touch it.
ALTER TABLE policies ADD COLUMN protected BOOLEAN NOT NULL DEFAULT false;
