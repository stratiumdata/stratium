// label-rules.tsx administers resource_label_rules: the table that decides
// what classification a resource carries, and therefore which requests a
// classification cap refuses.
//
// One field on this screen behaves unlike every other field in the console.
// See PREFIX_HINT.

import { useCallback, useMemo, useState } from 'react'

import { api, describeError, type ResourceLabelRule } from '../api'
import { Loading, useEditor, useList } from '../crud'
import {
  Button, ConfirmRow, EmptyRow, ErrorBanner, Field, Panel, ScreenHeader,
  TCell, THead, TRow, Table, TextInput,
} from '../ui'

/** An empty prefix is a prefix of every resource id, which makes the row the
 *  tenant's catch-all (R7) — the documented answer to "a cap was enabled and
 *  now everything denies". It is NOT a missing value, it is not invalid, and
 *  nothing here may require it: migrations/000019 deliberately omits the
 *  length(prefix) > 0 CHECK, and re-adding it in the browser would remove the
 *  one tenant-wide unblock from the screen most likely to be open when it is
 *  needed. */
const PREFIX_HINT = 'Leave empty to match every resource — this tenant’s catch-all.'

const BLANK: ResourceLabelRule = { id: '', tenant_id: '', prefix: '', hierarchy: '', level: '' }

export function LabelRulesScreen() {
  const { rows, error, reload } = useList<ResourceLabelRule>(api.resourceLabelRules)
  const [confirming, setConfirming] = useState<ResourceLabelRule | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  const res = useMemo(() => ({
    get: api.resourceLabelRule,
    create: api.createResourceLabelRule,
    update: api.updateResourceLabelRule,
    onSaved: reload,
  }), [reload])
  const editor = useEditor<ResourceLabelRule>(res)

  const remove = useCallback((r: ResourceLabelRule) => {
    api.deleteResourceLabelRule(r.id).then(
      () => { setConfirming(null); setActionError(null); reload() },
      (err: unknown) => { setConfirming(null); setActionError(describeError(err)) },
    )
  }, [reload])

  if (editor.draft !== null) {
    return (
      <Panel title={editor.editingID === null ? 'New resource label rule' : 'Edit resource label rule'} onClose={editor.close}>
        {editor.error ? <ErrorBanner>{editor.error}</ErrorBanner> : null}

        <Field label="Prefix" htmlFor="prefix" hint={PREFIX_HINT}>
          <TextInput
            id="prefix"
            value={editor.draft.prefix}
            onChange={(e) => editor.patch({ prefix: e.target.value })}
          />
        </Field>
        <Field label="Hierarchy" htmlFor="hierarchy" hint="Stored verbatim; never case-folded on the way in.">
          <TextInput
            id="hierarchy"
            value={editor.draft.hierarchy}
            onChange={(e) => editor.patch({ hierarchy: e.target.value })}
          />
        </Field>
        <Field label="Level" htmlFor="level" hint="Stored verbatim; never case-folded on the way in.">
          <TextInput
            id="level"
            value={editor.draft.level}
            onChange={(e) => editor.patch({ level: e.target.value })}
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
      <ScreenHeader title="Resource label rules">
        The longest matching prefix decides a resource&apos;s classification, and an
        unlabelled resource denies under any configured cap. A rule with an empty prefix
        matches everything and is this tenant&apos;s catch-all.
      </ScreenHeader>

      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {actionError ? <ErrorBanner>{actionError}</ErrorBanner> : null}
      {confirming ? (
        <div className="mb-4">
          <ConfirmRow
            prompt={confirming.prefix === ''
              ? 'Delete the catch-all? With no rule matching everything, unlabelled resources will deny under any configured cap.'
              : `Delete the rule for ${confirming.prefix}?`}
            confirmLabel="Delete rule"
            onConfirm={() => remove(confirming)}
            onCancel={() => setConfirming(null)}
          />
        </div>
      ) : null}

      <div className="mb-3">
        <Button onClick={() => editor.create(BLANK)}>New rule</Button>
      </div>

      {rows === null ? <Loading /> : (
        <Table>
          <THead columns={['Prefix', 'Hierarchy', 'Level', '']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={4}>No resource label rules.</EmptyRow> : rows.map((r) => (
              <TRow key={r.id}>
                <TCell className="font-mono">
                  {r.prefix === ''
                    ? <span className="text-muted-foreground">(empty) — matches every resource</span>
                    : r.prefix}
                </TCell>
                <TCell>{r.hierarchy}</TCell>
                <TCell>{r.level}</TCell>
                <TCell className="text-right">
                  <Button variant="ghost" size="sm" onClick={() => editor.edit(r.id)}>Edit</Button>
                  <Button variant="ghost" size="sm" onClick={() => setConfirming(r)}>Delete</Button>
                </TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}
