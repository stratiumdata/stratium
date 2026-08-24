import { api, type Agent } from '../api'
import { toolList, trustTier } from '../display'
import { Badge, EmptyRow, ErrorBanner, ScreenHeader, TCell, THead, TRow, Table } from '../ui'
import { Loading, useList } from '../crud'

// --- Agents -------------------------------------------------------------

export function AgentsScreen() {
  const { rows, error } = useList<Agent>(api.agents)
  return (
    <section>
      <ScreenHeader title="Agents">
        An empty allowed-tools list is unrestricted, not empty — the delegation is the real
        constraint.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Name', 'Provider', 'Model', 'Trust tier', 'State', 'Allowed tools']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={6}>No agents.</EmptyRow> : null}
            {rows.map((a) => (
              <TRow key={a.id}>
                <TCell className="font-medium">{a.name}</TCell>
                <TCell>{a.provider}</TCell>
                <TCell>{a.model_id}</TCell>
                <TCell>{trustTier(a.trust_tier)}</TCell>
                <TCell>
                  {a.suspended ? (
                    <Badge tone="warn">suspended</Badge>
                  ) : a.enabled ? (
                    <Badge tone="good">enabled</Badge>
                  ) : (
                    <Badge>disabled</Badge>
                  )}
                </TCell>
                <TCell>{toolList(a.allowed_tools)}</TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}
