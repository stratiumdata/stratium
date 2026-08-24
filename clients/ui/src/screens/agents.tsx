// agents.tsx administers the PAP's agents and, for each one, its
// classification-caps sub-resource -- the ceiling copied onto every root
// delegation issued for that agent.
//
// The two live at different role floors and travel on different routes.
// store.UpdateAgent's eight parameters (name, provider, model_id, trust_tier,
// enabled, suspended, allowed_tools, id) do not include classification_caps:
// GET returns the column, PUT ignores it on input. A caps field on the agent
// form would accept input, save without error, and change nothing -- an
// operator believing they had tightened a security ceiling that never moved.
// CapsSection below is the only thing on this screen that actually writes
// one, through its own route (RoleAdmin, where the agent body is RoleEditor).

import { useCallback, useEffect, useMemo, useState } from 'react'

import {
  api, describeError, type Agent, type AgentCapsView, type ClassificationCaps,
} from '../api'
import { toolList, trustTier } from '../display'
import { Loading, useEditor, useList } from '../crud'
import {
  Badge, Button, Checkbox, ConfirmRow, EmptyRow, ErrorBanner, Field, NumberInput, Panel,
  ScreenHeader, StringListInput, TCell, THead, TRow, Table, TextInput,
} from '../ui'

const BLANK: Agent = {
  id: '', name: '', provider: '', model_id: '', trust_tier: 0,
  enabled: true, suspended: false, allowed_tools: [], created_at: '', updated_at: '',
}

/** unsatisfiable_tools is NOT exhaustive for an unrestricted agent
 *  (allowed_tools == []): there is no finite tool list to scan, so an empty
 *  result there means only that every CATALOGUED tool is satisfiable, never
 *  that every tool is. The two cases are worded differently on purpose --
 *  an empty list for an unrestricted agent must not read as an all-clear. */
function unsatisfiableToolsMessage(tools: string[], allowedTools: string[]): string {
  const list = tools.join(', ')
  if (allowedTools.length === 0) {
    return tools.length > 0
      ? `Of the catalogued tools, these can never satisfy any cap: ${list}. ` +
        'Uncatalogued tools cannot be listed for an unrestricted agent.'
      : 'Of the catalogued tools, none can never satisfy any cap. ' +
        'Uncatalogued tools cannot be listed for an unrestricted agent.'
  }
  return tools.length > 0
    ? `These tools can never satisfy any cap: ${list}.`
    : 'No allowed tool for this agent is unsatisfiable for every cap.'
}

/** One hierarchy/level pair, held locally until Add hands it to the parent.
 *  A blank hierarchy or level is refused here rather than sent -- the server
 *  would refuse it too, but there is no reason to make a round trip find that
 *  out. */
function NewCapRow({ onAdd }: { onAdd: (hierarchy: string, level: string) => void }) {
  const [hierarchy, setHierarchy] = useState('')
  const [level, setLevel] = useState('')
  return (
    <div className="mb-3 flex flex-wrap items-end gap-2">
      <Field label="Hierarchy" htmlFor="new-cap-hierarchy">
        <TextInput id="new-cap-hierarchy" value={hierarchy} onChange={(e) => setHierarchy(e.target.value)} />
      </Field>
      <Field label="Level" htmlFor="new-cap-level">
        <TextInput id="new-cap-level" value={level} onChange={(e) => setLevel(e.target.value)} />
      </Field>
      <Button
        variant="outline"
        onClick={() => {
          if (hierarchy.trim() === '' || level.trim() === '') return
          onAdd(hierarchy.trim(), level.trim())
          setHierarchy('')
          setLevel('')
        }}
      >
        Add
      </Button>
    </div>
  )
}

/** The classification-caps panel. Loaded and saved independently of the
 *  agent form above it -- it is a different resource at a different role
 *  floor, not a field of this one.
 *
 *  AgentCapsView's own doc comment: "Every field beyond ClassificationCaps is
 *  advisory: setting a cap has consequences that are invisible in the stored
 *  value, and this type is where they are stated." A panel that rendered only
 *  the map would throw all of that away, so every advisory field is shown
 *  unconditionally, not just after a save:
 *
 *  - live_delegations/applies: "the delegations this cap does NOT affect. A
 *    warning, not a confirmation" -- caps are copied onto a delegation at
 *    issuance, so tightening a ceiling changes nothing already in flight.
 *  - unsatisfiable_tools: worded differently for a restricted vs. an
 *    unrestricted agent (see unsatisfiableToolsMessage above).
 *  - catch_all: shown beside each cap, since it is what an unlabelled
 *    resource resolves to and therefore what decides whether the cap bites.
 *
 *  Saving never sends ?allow_uncovered=true on the first attempt. When the
 *  server refuses a hierarchy with no catch-all rule, its message is shown
 *  verbatim and a separate "Apply anyway (uncovered)" control appears --
 *  acknowledging the refusal has to be its own deliberate click, never a
 *  flag silently carried on retry. */
function CapsSection({ agentID, allowedTools }: { agentID: string; allowedTools: string[] }) {
  const [view, setView] = useState<AgentCapsView | null>(null)
  const [caps, setCaps] = useState<ClassificationCaps>({})
  const [loadError, setLoadError] = useState<string | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [offerOverride, setOfferOverride] = useState(false)
  const [busy, setBusy] = useState(false)

  // Resets on every agentID change because the caller keys CapsSection by
  // agentID (see AgentsScreen below) and so remounts it -- no manual reset
  // of the other state here, which would mean calling setState synchronously
  // in the effect body (react-hooks/set-state-in-effect).
  useEffect(() => {
    let live = true
    api.agentCaps(agentID).then(
      (v) => { if (live) { setView(v); setCaps(v.classification_caps) } },
      (err: unknown) => { if (live) setLoadError(describeError(err)) },
    )
    return () => { live = false }
  }, [agentID])

  if (view === null) return loadError ? <ErrorBanner>{loadError}</ErrorBanner> : <Loading />

  const save = (allowUncovered: boolean) => {
    setBusy(true)
    setSaveError(null)
    const req = allowUncovered ? api.putAgentCaps(agentID, caps, true) : api.putAgentCaps(agentID, caps)
    req.then(
      (saved) => {
        setView(saved); setCaps(saved.classification_caps); setOfferOverride(false); setBusy(false)
      },
      (err: unknown) => { setSaveError(describeError(err)); setOfferOverride(true); setBusy(false) },
    )
  }

  const clear = () => {
    setBusy(true)
    setSaveError(null)
    api.deleteAgentCaps(agentID).then(
      () => {
        setCaps({})
        setView((v) => (v === null ? v : { ...v, classification_caps: {}, catch_all: {} }))
        setOfferOverride(false)
        setBusy(false)
      },
      (err: unknown) => { setSaveError(describeError(err)); setBusy(false) },
    )
  }

  const entries = Object.entries(caps)

  return (
    <section className="mt-6 border-t border-border pt-4">
      <h4 className="mb-1 text-sm font-semibold">Classification caps</h4>
      <p className="mb-3 text-xs text-muted-foreground">
        The per-hierarchy ceiling copied onto every root delegation for this agent. An empty
        set is the off switch. Set any cap and a resource with no label DENIES.
      </p>
      <p className="mb-3 text-xs text-muted-foreground">
        This takes effect {view.applies} — {view.live_delegations} live delegation
        {view.live_delegations === 1 ? '' : 's'} already {view.live_delegations === 1 ? 'carries' : 'carry'} the
        previous cap and {view.live_delegations === 1 ? 'is' : 'are'} unaffected: a warning, not a
        confirmation. Revoke {view.live_delegations === 1 ? 'it' : 'them'} on the Delegations screen to
        apply this now.
      </p>
      <p className="mb-3 text-xs text-muted-foreground">
        {unsatisfiableToolsMessage(view.unsatisfiable_tools, allowedTools)}
      </p>

      {loadError ? <ErrorBanner>{loadError}</ErrorBanner> : null}
      {saveError ? <ErrorBanner>{saveError}</ErrorBanner> : null}

      {entries.length === 0
        ? <p className="mb-3 text-sm text-muted-foreground">None — no classification ceiling is enforced for this agent.</p>
        : entries.map(([hierarchy, level]) => (
          <div key={hierarchy} className="mb-2 flex items-center gap-2">
            <span className="w-32 font-mono text-sm">{hierarchy}</span>
            <TextInput
              value={level}
              onChange={(e) => setCaps({ ...caps, [hierarchy]: e.target.value })}
            />
            <span className="text-xs text-muted-foreground">
              catch-all: {view.catch_all[hierarchy] ?? 'none'}
            </span>
            <Button variant="ghost" size="sm" onClick={() => {
              const next = { ...caps }; delete next[hierarchy]; setCaps(next)
            }}>
              Remove
            </Button>
          </div>
        ))}

      <NewCapRow onAdd={(h, l) => setCaps({ ...caps, [h]: l })} />

      <div className="mt-3 flex flex-wrap gap-2">
        <Button onClick={() => save(false)} disabled={busy}>Save caps</Button>
        <Button variant="destructive" onClick={clear} disabled={busy}>Clear all caps</Button>
        {offerOverride ? (
          <Button variant="outline" onClick={() => save(true)} disabled={busy}>
            Apply anyway (uncovered)
          </Button>
        ) : null}
      </div>
    </section>
  )
}

export function AgentsScreen() {
  const { rows, error, reload } = useList<Agent>(api.agents)
  const [confirming, setConfirming] = useState<Agent | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  // classification_caps is returned by GET and IGNORED by PUT (store.UpdateAgent
  // passes eight parameters and caps is not among them). Sending it back would
  // put a field on the wire that silently does nothing; caps are written through
  // their own route in CapsSection above.
  const res = useMemo(() => ({
    get: api.agent,
    create: api.createAgent,
    update: (id: string, a: Agent) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars -- discarded on purpose, see above.
      const { classification_caps: _ignored, ...body } = a as Agent & { classification_caps?: unknown }
      return api.updateAgent(id, body)
    },
    onSaved: reload,
  }), [reload])
  const editor = useEditor<Agent>(res)

  const remove = useCallback((a: Agent) => {
    api.deleteAgent(a.id).then(
      () => { setConfirming(null); setActionError(null); reload() },
      (err: unknown) => { setConfirming(null); setActionError(describeError(err)) },
    )
  }, [reload])

  if (editor.draft !== null) {
    return (
      <Panel title={editor.editingID === null ? 'New agent' : 'Edit agent'} onClose={editor.close}>
        {editor.error ? <ErrorBanner>{editor.error}</ErrorBanner> : null}

        <Field label="Name" htmlFor="name">
          <TextInput id="name" value={editor.draft.name} onChange={(e) => editor.patch({ name: e.target.value })} />
        </Field>
        <Field label="Provider" htmlFor="provider">
          <TextInput
            id="provider"
            value={editor.draft.provider}
            onChange={(e) => editor.patch({ provider: e.target.value })}
          />
        </Field>
        <Field label="Model ID" htmlFor="model_id">
          <TextInput
            id="model_id"
            value={editor.draft.model_id}
            onChange={(e) => editor.patch({ model_id: e.target.value })}
          />
        </Field>
        <Field label="Trust tier" htmlFor="trust_tier">
          <NumberInput
            id="trust_tier"
            min={0}
            max={3}
            value={editor.draft.trust_tier}
            onChange={(e) => editor.patch({ trust_tier: Number(e.target.value) })}
          />
        </Field>
        <Checkbox
          id="enabled"
          label="Enabled"
          checked={editor.draft.enabled}
          onChange={(e) => editor.patch({ enabled: e.target.checked })}
        />
        <Checkbox
          id="suspended"
          label="Suspended"
          checked={editor.draft.suspended}
          onChange={(e) => editor.patch({ suspended: e.target.checked })}
        />
        <Field label="Allowed tools" htmlFor="allowed_tools" hint="One per line. Empty means unrestricted.">
          <StringListInput
            value={editor.draft.allowed_tools}
            onChange={(next) => editor.patch({ allowed_tools: next })}
          />
        </Field>

        <div className="mt-4 flex gap-2">
          <Button onClick={editor.save} disabled={editor.busy}>Save</Button>
          <Button variant="outline" onClick={editor.close}>Cancel</Button>
        </div>

        {editor.editingID !== null ? (
          <CapsSection key={editor.editingID} agentID={editor.editingID} allowedTools={editor.draft.allowed_tools} />
        ) : null}
      </Panel>
    )
  }

  return (
    <section>
      <ScreenHeader title="Agents">
        An empty allowed-tools list is unrestricted, not empty — the delegation is the real
        constraint. Classification caps are set separately, below, once an agent exists.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {actionError ? <ErrorBanner>{actionError}</ErrorBanner> : null}
      {confirming ? (
        <div className="mb-4">
          <ConfirmRow
            prompt={`Delete agent ${confirming.name}?`}
            confirmLabel="Delete agent"
            onConfirm={() => remove(confirming)}
            onCancel={() => setConfirming(null)}
          />
        </div>
      ) : null}

      <div className="mb-3">
        <Button onClick={() => editor.create(BLANK)}>New agent</Button>
      </div>

      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Name', 'Provider', 'Model', 'Trust tier', 'State', 'Allowed tools', '']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={7}>No agents.</EmptyRow> : rows.map((a) => (
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
                <TCell className="text-right">
                  <Button variant="ghost" size="sm" onClick={() => editor.edit(a.id)}>Edit</Button>
                  <Button variant="ghost" size="sm" onClick={() => setConfirming(a)}>Delete</Button>
                </TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}
