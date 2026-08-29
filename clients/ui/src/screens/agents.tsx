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
  APIError, ID_PREFIX, api, describeError, type Agent, type AgentCapsView,
  type AgentConstraintsView, type ClassificationCaps, type ResourceConstraints,
} from '../api'
import { TRUST_TIERS, toolList, trustTier, trustTierOptions } from '../display'
import { Loading, useEditor, useList } from '../crud'
import {
  Badge, Button, Checkbox, ConfirmRow, EmptyRow, ErrorBanner, Field, Panel,
  ScreenHeader, Select, StringListInput, TCell, THead, TRow, Table, TextInput,
} from '../ui'

/** Agent minus its two sub-resources -- what UpdateAgent's PUT actually
 *  writes. Shared by the editor's `update` and `compare` below so the two can
 *  never drift apart: the clobber guard must compare exactly what gets sent,
 *  or a cap changed through CapsSection's own route reads as a colleague's
 *  concurrent edit of the agent.
 *
 *  resource_constraints joins classification_caps here for the same reason
 *  and with the same consequence. Both are returned by GET and absent from
 *  updateAgentQuery's SET clause, so sending either back is a write that
 *  silently does nothing -- and leaving either in `compare` turns a scope
 *  edited through its own panel into a phantom conflict. */
function withoutSubresources(a: Agent): Omit<Agent, 'classification_caps' | 'resource_constraints'> {
  const {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- discarded on purpose, see above.
    classification_caps: _caps,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- discarded on purpose, see above.
    resource_constraints: _constraints,
    ...body
  } = a as Agent & { classification_caps?: unknown; resource_constraints?: unknown }
  return body
}

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
      <Field label="Hierarchy" htmlFor="new-cap-hierarchy"
        hint={"A classification namespace, e.g. nato. Stored exactly as typed — never case-folded."}
      >
        <TextInput id="new-cap-hierarchy" value={hierarchy} onChange={(e) => setHierarchy(e.target.value)} />
      </Field>
      <Field label="Level" htmlFor="new-cap-level"
        hint={"The ceiling within that hierarchy. Each hierarchy defines its own levels, so one that is valid in another is refused here — the server names the accepted list when it refuses. Stored exactly as typed."}
      >
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
  const [confirmingClear, setConfirmingClear] = useState(false)
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
      (err: unknown) => {
        // Offer the override only for the coverage refusal itself, never for
        // any other save failure (a 502, a 403, ...) -- the server's message
        // names its own query parameter, so matching on it is how this repo
        // tells the coverage refusal apart from any other rejection.
        setSaveError(describeError(err))
        setOfferOverride(err instanceof APIError && err.message.includes('allow_uncovered'))
        setBusy(false)
      },
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
        setConfirmingClear(false)
        setBusy(false)
      },
      (err: unknown) => { setSaveError(describeError(err)); setConfirmingClear(false); setBusy(false) },
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

      {saveError ? <ErrorBanner>{saveError}</ErrorBanner> : null}

      {/* Clearing is the loosening direction: it removes the whole ceiling in
         one click, unlike a single Remove above which only narrows what is
         capped. Every other destructive action on this branch is gated
         behind ConfirmRow -- this is the one that was not. */}
      {confirmingClear ? (
        <div className="mb-3">
          <ConfirmRow
            prompt="Clear all caps? With no caps set, no classification ceiling is enforced for this agent."
            confirmLabel="Yes, clear all caps"
            busyLabel="Clearing…"
            busy={busy}
            onConfirm={clear}
            onCancel={() => setConfirmingClear(false)}
          />
        </div>
      ) : null}

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
        <Button variant="destructive" onClick={() => setConfirmingClear(true)} disabled={busy}>
          Clear all caps
        </Button>
        {offerOverride ? (
          <Button variant="outline" onClick={() => save(true)} disabled={busy}>
            Apply anyway (uncovered)
          </Button>
        ) : null}
      </div>
    </section>
  )
}

/** Rejects a scope prefix the server would reject, in the same order and for
 *  the same reasons (internal/store's validateResourceConstraints). Returns
 *  null when it is acceptable.
 *
 *  A courtesy, never the enforcement: the server stays authoritative and its
 *  refusal is rendered verbatim if the two ever disagree. The trailing slash
 *  is the one worth catching at the field, because its absence is silent
 *  rather than loud -- "/workspace" also matches "/workspace-evil/secrets.txt",
 *  and an operator is better told that while looking at what they typed. */
function scopeProblem(prefix: string): string | null {
  if (prefix === '') return 'A scope prefix must not be empty. Use Clear scope to remove the scope.'
  if (prefix.includes('..')) return 'A scope prefix must not contain "..".'
  if (!prefix.endsWith('/')) {
    return `A scope prefix must end in "/" — did you mean "${prefix}/"? ` +
      `Without it, "${prefix}" also matches siblings such as "${prefix}-other/secrets".`
  }
  return null
}

/** The resource-constraints panel: one scope, not a map editor.
 *
 *  models.Delegation.ResourceConstraints is a map, and the caps panel above
 *  edits its map as a map. This one deliberately does not. Only `id_prefix`
 *  means anything to a supported flow; every other key is an exact-match
 *  constraint compared against a resource attribute the request carries, the
 *  PDP only ever produces `id`, and never for a shell call -- so a key typed
 *  here would deny every call for this agent, silently and permanently. A
 *  generic editor would make that one typo away. See ResourceConstraints'
 *  own doc comment in api.ts.
 *
 *  Advisory fields are shown unconditionally, for the reason AgentCapsView's
 *  doc comment gives and AgentConstraintsView repeats: setting a scope has
 *  consequences the stored value does not show, and the server is where they
 *  are stated. `applies` is rendered rather than phrased here, so the
 *  semantics live in one language, not two.
 *
 *  unsatisfiable_tools is deliberately NOT rendered here: it is the same
 *  set the caps panel above already states unconditionally, and a second
 *  copy would put one sentence on screen twice. What a scope reader needs
 *  from it -- that a call naming no path is denied -- is said in scope's
 *  own terms in the paragraphs below. */
function ScopeSection({ agentID }: { agentID: string }) {
  const [view, setView] = useState<AgentConstraintsView | null>(null)
  const [prefix, setPrefix] = useState('')
  const [loadError, setLoadError] = useState<string | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [confirmingClear, setConfirmingClear] = useState(false)
  const [busy, setBusy] = useState(false)

  // Keyed by agentID at the call site, so a remount resets everything -- the
  // same reason CapsSection above resets nothing by hand.
  useEffect(() => {
    let live = true
    api.agentConstraints(agentID).then(
      (v) => { if (live) { setView(v); setPrefix(v.resource_constraints[ID_PREFIX] ?? '') } },
      (err: unknown) => { if (live) setLoadError(describeError(err)) },
    )
    return () => { live = false }
  }, [agentID])

  if (view === null) return loadError ? <ErrorBanner>{loadError}</ErrorBanner> : <Loading />

  const save = () => {
    const problem = scopeProblem(prefix)
    if (problem !== null) { setSaveError(problem); return }
    setBusy(true)
    setSaveError(null)
    const constraints: ResourceConstraints = { [ID_PREFIX]: prefix }
    api.putAgentConstraints(agentID, constraints).then(
      (saved) => {
        setView(saved); setPrefix(saved.resource_constraints[ID_PREFIX] ?? ''); setBusy(false)
      },
      (err: unknown) => { setSaveError(describeError(err)); setBusy(false) },
    )
  }

  const clear = () => {
    setBusy(true)
    setSaveError(null)
    api.deleteAgentConstraints(agentID).then(
      () => {
        setPrefix('')
        setView((v) => (v === null ? v : { ...v, resource_constraints: {} }))
        setConfirmingClear(false)
        setBusy(false)
      },
      (err: unknown) => { setSaveError(describeError(err)); setConfirmingClear(false); setBusy(false) },
    )
  }

  const stored = view.resource_constraints[ID_PREFIX]

  return (
    <section className="mt-6 border-t border-border pt-4">
      <h4 className="mb-1 text-sm font-semibold">Scope</h4>
      <p className="mb-3 text-xs text-muted-foreground">
        Limits this agent to one resource subtree, copied onto every root delegation. EVERY path a
        call names must be inside it — a command naming one path outside is denied, so a benign
        path cannot buy access for a dangerous one. A command naming no path at all is denied too.
      </p>
      <p className="mb-3 text-xs text-muted-foreground">
        The prefix is matched literally, so the root is outside its own scope: under{' '}
        <span className="font-mono">/workspace/</span>, a call naming{' '}
        <span className="font-mono">/workspace</span> is denied. A path containing{' '}
        <span className="font-mono">..</span> is denied outright rather than resolved.
      </p>
      <p className="mb-3 text-xs text-muted-foreground">
        This takes effect {view.applies} — {view.live_delegations} live delegation
        {view.live_delegations === 1 ? '' : 's'} already{' '}
        {view.live_delegations === 1 ? 'carries' : 'carry'} the previous scope and{' '}
        {view.live_delegations === 1 ? 'is' : 'are'} unaffected: a warning, not a confirmation.
        Revoke {view.live_delegations === 1 ? 'it' : 'them'} on the Delegations screen to apply
        this now.
      </p>
      {saveError ? <ErrorBanner>{saveError}</ErrorBanner> : null}

      {/* Clearing removes the whole ceiling in one click -- the loosening
         direction, gated exactly as clearing caps is. */}
      {confirmingClear ? (
        <div className="mb-3">
          <ConfirmRow
            prompt="Clear the scope? With none set, this agent is not limited to any subtree."
            confirmLabel="Yes, clear the scope"
            busyLabel="Clearing…"
            busy={busy}
            onConfirm={clear}
            onCancel={() => setConfirmingClear(false)}
          />
        </div>
      ) : null}

      {stored === undefined
        ? <p className="mb-3 text-sm text-muted-foreground">None — this agent is not scoped to any subtree.</p>
        : null}

      <div className="mb-2 flex items-center gap-2">
        <label htmlFor="scope-prefix" className="w-32 text-sm">Scope prefix</label>
        <TextInput
          id="scope-prefix"
          value={prefix}
          placeholder="/workspace/"
          onChange={(e) => setPrefix(e.target.value)}
        />
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        <Button onClick={save} disabled={busy}>Save scope</Button>
        <Button variant="destructive" onClick={() => setConfirmingClear(true)} disabled={busy}>
          Clear scope
        </Button>
      </div>
    </section>
  )
}

export function AgentsScreen() {
  const { rows, error, reload } = useList<Agent>(api.agents)
  const [confirming, setConfirming] = useState<Agent | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [removing, setRemoving] = useState<string | null>(null)

  // classification_caps is returned by GET and IGNORED by PUT (store.UpdateAgent
  // passes eight parameters and caps is not among them). Sending it back would
  // put a field on the wire that silently does nothing; caps are written through
  // their own route in CapsSection above. The clobber guard's `compare` strips
  // the same field for the same reason: it is never part of what this form
  // writes, so a change to it alone is not a concurrent edit of the agent.
  const res = useMemo(() => ({
    get: api.agent,
    create: api.createAgent,
    update: (id: string, a: Agent) => api.updateAgent(id, withoutSubresources(a)),
    compare: withoutSubresources,
    onSaved: reload,
  }), [reload])
  const editor = useEditor<Agent>(res)

  const remove = useCallback((a: Agent) => {
    setRemoving(a.id)
    api.deleteAgent(a.id).then(
      () => { setConfirming(null); setActionError(null); setRemoving(null); reload() },
      (err: unknown) => { setConfirming(null); setActionError(describeError(err)); setRemoving(null) },
    )
  }, [reload])

  if (editor.draft !== null) {
    return (
      <Panel title={editor.editingID === null ? 'New agent' : 'Edit agent'} onClose={editor.close}>
        {editor.error ? <ErrorBanner>{editor.error}</ErrorBanner> : null}

        <Field label="Name" htmlFor="name"
          hint={"Required, and unique within this tenant."}
        >
          <TextInput id="name" value={editor.draft.name} onChange={(e) => editor.patch({ name: e.target.value })} />
        </Field>
        <Field label="Provider" htmlFor="provider"
          hint={"Required — the vendor serving the model, e.g. anthropic."}
        >
          <TextInput
            id="provider"
            value={editor.draft.provider}
            onChange={(e) => editor.patch({ provider: e.target.value })}
          />
        </Field>
        <Field label="Model ID" htmlFor="model_id"
          hint={"Optional. Recorded for identification; not validated."}
        >
          <TextInput
            id="model_id"
            value={editor.draft.model_id}
            onChange={(e) => editor.patch({ model_id: e.target.value })}
          />
        </Field>
        <Field label="Trust tier" htmlFor="trust_tier"
          hint={"The floor the PDP enforces per action tier: REGISTERED for INTERNAL_MODIFY, CERTIFIED for EXTERNAL_COMMS, PLATFORM_TRUSTED for DESTRUCTIVE. UNVERIFIED reaches only REASONING and READ_ONLY."}
        >
          {/* The option's index IS the tier, so the name shown and the number
              sent cannot drift apart. An out-of-range stored value appears as
              itself: a select whose value matches no option renders the FIRST
              one, which would claim UNVERIFIED for an agent that is not. */}
          <Select
            id="trust_tier"
            options={trustTierOptions(editor.draft.trust_tier)}
            value={trustTier(editor.draft.trust_tier)}
            onChange={(e) => {
              const tier = TRUST_TIERS.indexOf(e.target.value)
              // -1 is the INVALID_ option, which stands for the value already
              // stored; picking it changes nothing rather than writing -1.
              if (tier >= 0) editor.patch({ trust_tier: tier })
            }}
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
          <>
            <CapsSection key={editor.editingID} agentID={editor.editingID} allowedTools={editor.draft.allowed_tools} />
            <ScopeSection key={`scope-${editor.editingID}`} agentID={editor.editingID} />
          </>
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
      {/* useEditor's edit() can reject before the panel that would normally
         show editor.error ever opens -- draft stays null on a failed GET (a
         colleague deleted the row, a 500, a network blip), so this is the
         one place editor.error is rendered outside the panel. */}
      {editor.error ? <ErrorBanner>{editor.error}</ErrorBanner> : null}
      {confirming ? (
        <div className="mb-4">
          <ConfirmRow
            prompt={`Delete agent ${confirming.name}?`}
            confirmLabel="Delete agent"
            busyLabel="Deleting…"
            busy={removing === confirming.id}
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
