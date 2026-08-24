import { useMemo } from 'react'

import { api, type ToolCatalogEntry } from '../api'
import { ACTION_TIERS, actionTier, actionTierOptions } from '../display'
import { Loading, useEditor, useList } from '../crud'
import {
  Button, Checkbox, EmptyRow, ErrorBanner, Field, Panel, ScreenHeader, Select,
  TCell, THead, TRow, Table, TextInput,
} from '../ui'

// --- Tool catalog -------------------------------------------------------

// resource_field and command_field are *string with omitempty in Go. Sending
// "" is NOT the same as omitting them: it produces a non-nil pointer to the
// empty string, which defeats BOTH guards on this table --
// store.CreateToolCatalogEntry refuses only `ActionTier == nil &&
// CommandField == nil` (internal/store/catalog.go), and the database's
// tool_catalog_tier_or_command_field CHECK tests `IS NOT NULL`. An empty
// string passes each, and the row it stores means "derive the tier from the
// field named empty-string". They stay absent until an operator types one.
const BLANK: ToolCatalogEntry = { id: '', tool_name: '', action_tier: null, verb: '' }

/** '' means "not set" for the two optional field names, and must be omitted
 *  from the payload rather than sent. See BLANK. */
const orUndefined = (v: string) => (v === '' ? undefined : v)

export function ToolCatalogScreen() {
  const { rows, error, reload } = useList<ToolCatalogEntry>(api.toolCatalog)

  const res = useMemo(() => ({
    get: api.toolCatalogEntry,
    create: api.createToolCatalogEntry,
    update: api.updateToolCatalogEntry,
    onSaved: reload,
  }), [reload])
  const editor = useEditor<ToolCatalogEntry>(res)

  if (editor.draft !== null) {
    return (
      <Panel title={editor.editingID === null ? 'New tool catalog entry' : 'Edit tool catalog entry'} onClose={editor.close}>
        {editor.error ? <ErrorBanner>{editor.error}</ErrorBanner> : null}

        <Field label="Tool name" htmlFor="tool_name"
          hint={"Must match the name the agent actually calls, e.g. Read. An uncatalogued tool is not a hole — a delegation must already hold it before this row matters."}
        >
          <TextInput
            id="tool_name"
            value={editor.draft.tool_name}
            onChange={(e) => editor.patch({ tool_name: e.target.value })}
          />
        </Field>
        <Field label="Verb" htmlFor="verb"
          hint={"Recorded, but not yet read by any decision: tier lookups use the verb on the incoming call, not this column."}
        >
          <TextInput
            id="verb"
            value={editor.draft.verb}
            onChange={(e) => editor.patch({ verb: e.target.value })}
          />
        </Field>

        <Checkbox
          label="Derive the tier from the command"
          checked={editor.draft.action_tier === null}
          onChange={(e) => editor.patch({ action_tier: e.target.checked ? null : 0 })}
        />
        {editor.draft.action_tier !== null ? (
          <Field label="Action tier" htmlFor="action_tier"
            hint={"A fixed tier for every call to this tool. Leave it derived unless the tool always carries the same risk."}
          >
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
        ) : null}

        <Field label="Resource field" htmlFor="resource_field"
          hint="Names the argument holding the resource id, for label-based caps.">
          <TextInput
            id="resource_field"
            value={editor.draft.resource_field ?? ''}
            onChange={(e) => editor.patch({ resource_field: orUndefined(e.target.value) })}
          />
        </Field>
        <Field label="Command field" htmlFor="command_field"
          hint="Required when the tier is derived: it names the argument holding the command to classify.">
          <TextInput
            id="command_field"
            value={editor.draft.command_field ?? ''}
            onChange={(e) => editor.patch({ command_field: orUndefined(e.target.value) })}
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
      <ScreenHeader title="Tool catalog">
        A tool with no action tier is classified per invocation from its command field —
        the shell-shaped case, where one tool name covers both a harmless read and a
        destructive command.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {/* useEditor's edit() can reject before the panel that would normally
         show editor.error ever opens -- draft stays null on a failed GET (a
         colleague deleted the row, a 500, a network blip), so this is the
         one place editor.error is rendered outside the panel. */}
      {editor.error ? <ErrorBanner>{editor.error}</ErrorBanner> : null}

      <div className="mb-3">
        <Button onClick={() => editor.create(BLANK)}>New entry</Button>
      </div>

      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Tool', 'Verb', 'Action tier', 'Resource field', 'Command field', '']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={6}>No tool catalog entries.</EmptyRow> : rows.map((e) => (
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
                <TCell className="text-right">
                  <Button variant="ghost" size="sm" onClick={() => editor.edit(e.id)}>Edit</Button>
                </TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}
