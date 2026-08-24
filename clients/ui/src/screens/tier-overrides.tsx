import { useCallback, useMemo, useState } from 'react'

import { api, describeError, type TierOverride } from '../api'
import { ACTION_TIERS, actionTier, actionTierOptions, timestamp } from '../display'
import { Loading, useEditor, useList } from '../crud'
import {
  Button, ConfirmRow, EmptyRow, ErrorBanner, Field, Panel, ScreenHeader, Select,
  TCell, THead, TRow, Table, TextInput,
} from '../ui'

// --- Tier overrides -----------------------------------------------------

/** internal/store/tier_override.go: ID, TenantID, BuiltinTier, CreatedAt and
 *  CreatedBy are ignored on input and set authoritatively by the store --
 *  BuiltinTier specifically must never be operator-supplied. An input for any
 *  of them would accept a value that is silently discarded, so this form
 *  offers exactly two: tool_or_verb and action_tier. The builtin tier is
 *  shown read-only beside the override in the list, so the operator can see
 *  what is being overridden. */
const BLANK: TierOverride = {
  id: '', tool_or_verb: '', action_tier: 0, builtin_tier: 0, created_at: '', created_by: '',
}

export function TierOverridesScreen() {
  const { rows, error, reload } = useList<TierOverride>(api.tierOverrides)
  const [confirming, setConfirming] = useState<TierOverride | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [removing, setRemoving] = useState<string | null>(null)

  const res = useMemo(() => ({
    get: api.tierOverride,
    create: api.createTierOverride,
    update: api.updateTierOverride,
    onSaved: reload,
  }), [reload])
  const editor = useEditor<TierOverride>(res)

  const remove = useCallback((o: TierOverride) => {
    setRemoving(o.id)
    api.deleteTierOverride(o.id).then(
      () => { setConfirming(null); setActionError(null); setRemoving(null); reload() },
      (err: unknown) => { setConfirming(null); setActionError(describeError(err)); setRemoving(null) },
    )
  }, [reload])

  if (editor.draft !== null) {
    return (
      <Panel title={editor.editingID === null ? 'New tier override' : 'Edit tier override'} onClose={editor.close}>
        {editor.error ? <ErrorBanner>{editor.error}</ErrorBanner> : null}

        <Field label="Tool or verb" htmlFor="tool_or_verb">
          <TextInput
            id="tool_or_verb"
            value={editor.draft.tool_or_verb}
            onChange={(e) => editor.patch({ tool_or_verb: e.target.value })}
          />
        </Field>
        <Field label="Action tier" htmlFor="action_tier"
          hint="Overrides the builtin tier, which the server computes and this form cannot set.">
          <Select
            id="action_tier"
            options={actionTierOptions(editor.draft.action_tier)}
            value={actionTier(editor.draft.action_tier)}
            onChange={(e) => {
              const tier = ACTION_TIERS.indexOf(e.target.value)
              // -1 is the INVALID_ option, standing for the value already
              // stored; picking it changes nothing rather than writing -1.
              if (tier >= 0) editor.patch({ action_tier: tier })
            }}
          />
        </Field>

        <div className="mt-4 flex gap-2">
          <Button onClick={editor.save} disabled={editor.busy}>Save</Button>
          <Button variant="outline" onClick={editor.close}>Cancel</Button>
        </div>
      </Panel>
    )
  }

  return (
    <section>
      <ScreenHeader title="Tier overrides">
        An override may only raise a tool's built-in tier, never lower it. The built-in
        column is derived by the server and is what the override was validated against.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {actionError ? <ErrorBanner>{actionError}</ErrorBanner> : null}
      {/* useEditor's edit() can reject before the panel that would normally
         show editor.error ever opens -- draft stays null on a failed GET (a
         colleague deleted the row, a 500, a network blip), so this is the
         one place editor.error is rendered outside the panel. */}
      {editor.error ? <ErrorBanner>{editor.error}</ErrorBanner> : null}
      {confirming ? (
        <div className="mb-4">
          <ConfirmRow
            prompt={`Delete the override for ${confirming.tool_or_verb}?`}
            confirmLabel="Delete override"
            busyLabel="Deleting…"
            busy={removing === confirming.id}
            onConfirm={() => remove(confirming)}
            onCancel={() => setConfirming(null)}
          />
        </div>
      ) : null}

      <div className="mb-3">
        <Button onClick={() => editor.create(BLANK)}>New override</Button>
      </div>

      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Tool or verb', 'Override tier', 'Built-in tier', 'Created', 'By', '']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={6}>No tier overrides.</EmptyRow> : rows.map((o) => (
              <TRow key={o.id}>
                <TCell className="font-medium">{o.tool_or_verb}</TCell>
                <TCell>{actionTier(o.action_tier)}</TCell>
                <TCell className="text-muted-foreground">{actionTier(o.builtin_tier)}</TCell>
                <TCell>{timestamp(o.created_at)}</TCell>
                <TCell>{o.created_by}</TCell>
                <TCell className="text-right">
                  <Button variant="ghost" size="sm" onClick={() => editor.edit(o.id)}>Edit</Button>
                  <Button variant="ghost" size="sm" onClick={() => setConfirming(o)}>Delete</Button>
                </TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}
