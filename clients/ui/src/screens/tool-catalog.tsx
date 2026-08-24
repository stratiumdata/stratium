import { api, type ToolCatalogEntry } from '../api'
import { actionTier } from '../display'
import { EmptyRow, ErrorBanner, ScreenHeader, TCell, THead, TRow, Table } from '../ui'
import { Loading, useList } from '../crud'

// --- Tool catalog -------------------------------------------------------

export function ToolCatalogScreen() {
  const { rows, error } = useList<ToolCatalogEntry>(api.toolCatalog)
  return (
    <section>
      <ScreenHeader title="Tool catalog">
        A tool with no action tier is classified per invocation from its command field —
        the shell-shaped case, where one tool name covers both a harmless read and a
        destructive command.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Tool', 'Verb', 'Action tier', 'Resource field', 'Command field']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={5}>No catalog entries.</EmptyRow> : null}
            {rows.map((e) => (
              <TRow key={e.id}>
                <TCell className="font-medium">{e.tool_name}</TCell>
                <TCell>{e.verb}</TCell>
                <TCell>
                  {e.action_tier === null ? (
                    <span className="text-muted-foreground">per invocation</span>
                  ) : (
                    actionTier(e.action_tier)
                  )}
                </TCell>
                <TCell>{e.resource_field ?? '—'}</TCell>
                <TCell>{e.command_field ?? '—'}</TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}
