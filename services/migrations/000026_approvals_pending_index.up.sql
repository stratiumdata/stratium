-- The PDP looks up a session's pending approvals on every escalation, to
-- return one already waiting for the same call and to hold the session to a
-- maximum. Most rows are answered or expired; this indexes only the rest.
CREATE INDEX idx_approvals_pending_root ON approvals(root_delegation_id) WHERE status = 'pending';
