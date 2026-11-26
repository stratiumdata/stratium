-- One row for each session with calls in the recent past: what is left of its
-- call budget (STRATIUM_SESSION_CALLS_PER_SECOND and _BURST). Every PDP for a
-- tenant draws on the same row, so the rate holds across them. A PDP takes
-- tokens in blocks and spends them from memory; this table is written about
-- once per block, not once per call.
--
-- UNLOGGED: a counter that is wrong for a moment costs nothing, and a crash
-- that empties this table leaves every session with a full budget, which is
-- what a session with no row has anyway. In exchange a write here is not a
-- write to the log on the path of every decision.
CREATE UNLOGGED TABLE session_budgets (
    -- A root delegation's id. Not a foreign key: the row is a counter about a
    -- session, kept only while it is busy, and nothing should refuse or
    -- cascade on its account.
    session_id UUID PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    -- Tokens left as of updated_at. They refill with time, so the true figure
    -- is computed when the row is next touched.
    tokens     DOUBLE PRECISION NOT NULL CHECK (tokens >= 0),
    -- How many the last lease took, so the statement that takes them can
    -- return the number.
    last_taken INTEGER NOT NULL CHECK (last_taken >= 0),
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_session_budgets_tenant_updated ON session_budgets(tenant_id, updated_at);

ALTER TABLE session_budgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_budgets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON session_budgets
    USING (tenant_id = current_tenant())
    WITH CHECK (tenant_id = current_tenant());

-- The PDP alone reads and writes this. DELETE is for its sweep of rows no
-- session has touched in a while.
GRANT SELECT, INSERT, UPDATE, DELETE ON session_budgets TO stratium_app;
