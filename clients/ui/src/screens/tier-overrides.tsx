import { api, type TierOverride } from '../api'
import { actionTier, timestamp } from '../display'
import { EmptyRow, ErrorBanner, ScreenHeader, TCell, THead, TRow, Table } from '../ui'
import { Loading, useList } from '../crud'

// --- Tier overrides -----------------------------------------------------

export function TierOverridesScreen() {
  const { rows, error } = useList<TierOverride>(api.tierOverrides)
  return (
    <section>
      <ScreenHeader title="Tier overrides">
        An override may only raise a tool's built-in tier, never lower it. The built-in
        column is derived by the server and is what the override was validated against.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Tool or verb', 'Override tier', 'Built-in tier', 'Created', 'By']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={5}>No tier overrides.</EmptyRow> : null}
            {rows.map((o) => (
              <TRow key={o.id}>
                <TCell className="font-medium">{o.tool_or_verb}</TCell>
                <TCell>{actionTier(o.action_tier)}</TCell>
                <TCell className="text-muted-foreground">{actionTier(o.builtin_tier)}</TCell>
                <TCell>{timestamp(o.created_at)}</TCell>
                <TCell>{o.created_by}</TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}
