import { api, type Policy } from '../api'
import { policyEffect, timestamp } from '../display'
import { Badge, EmptyRow, ErrorBanner, ScreenHeader, TCell, THead, TRow, Table } from '../ui'
import { Loading, useList } from '../crud'

// --- Policies -----------------------------------------------------------

export function PoliciesScreen() {
  const { rows, error } = useList<Policy>(api.policies)
  return (
    <section>
      <ScreenHeader title="Policies">
        A policy's effect is shown only for the two languages where the stored value is
        checked against the policy text at write time. A Rego or XACML policy can define
        rules of both effects, resolved only when a request is evaluated, so no effect is
        claimed for one.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Name', 'Language', 'Effect', 'Version', 'Enabled', 'Updated']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={6}>No policies.</EmptyRow> : null}
            {rows.map((p) => {
              const effect = policyEffect(p.language, p.effect)
              return (
                <TRow key={p.id}>
                  <TCell>
                    <div className="font-medium">{p.name}</div>
                    {p.description ? (
                      <div className="text-xs text-muted-foreground">{p.description}</div>
                    ) : null}
                  </TCell>
                  <TCell>{p.language}</TCell>
                  <TCell>
                    {effect.kind === 'declared' ? (
                      <Badge tone={effect.effect === 'allow' ? 'good' : 'warn'}>{effect.effect}</Badge>
                    ) : (
                      <span title={effect.reason} className="text-muted-foreground">
                        determined at evaluation
                      </span>
                    )}
                  </TCell>
                  <TCell>{p.version}</TCell>
                  <TCell>{p.enabled ? 'yes' : 'no'}</TCell>
                  <TCell>{timestamp(p.updated_at)}</TCell>
                </TRow>
              )
            })}
          </tbody>
        </Table>
      )}
    </section>
  )
}
