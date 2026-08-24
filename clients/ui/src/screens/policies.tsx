// policies.tsx administers models.Policy: the four-language rule store the
// PDP folds on every decision. This is the largest screen because it is the
// only one with three server round-trips beyond CRUD -- the language list,
// Validate, and the two-legged Test -- each with its own failure shape.
//
// Two things here are not obvious from the field list alone:
//
// - `effect` is operator-choosable only for cedar and json (declaresEffect,
//   display.ts). For rego and xacml the store refuses any value but the
//   fixed placeholder "deny" outright, so the draft's effect is PINNED
//   whenever the language changes to one that cannot declare it, rather than
//   carrying the previous choice into a guaranteed rejection.
// - The Test panel renders TWO verdicts, not one -- see TestResultView below.

import { useCallback, useEffect, useMemo, useState } from 'react'

import {
  api, describeError,
  type Policy, type PolicyTestLeg, type PolicyTestRequest, type PolicyTestResult,
} from '../api'
import { actionTier, declaresEffect, policyEffect, timestamp } from '../display'
import { Loading, useEditor, useList, type Editor } from '../crud'
import {
  Badge, Button, Checkbox, ConfirmRow, EmptyRow, ErrorBanner, Field, Panel,
  ScreenHeader, Select, TCell, TextInput, Textarea, THead, TRow, Table,
} from '../ui'

const BLANK: Policy = {
  id: '', name: '', description: '', language: '', policy_content: '',
  effect: 'deny', version: 0, enabled: true, created_at: '', updated_at: '',
}

/** A complete, valid test request for the given language and text, so the
 *  textarea's prefill documents the request shape rather than an operator
 *  having to consult this file to learn it. */
function blankTestRequest(language: string, text: string): string {
  const req: PolicyTestRequest = {
    language,
    policy_content: text,
    principal: { subject: 'operator@example.com', attributes: {} },
    action: { tool: 'Read', raw_input: '{"file_path":"/tmp/notes.txt"}' },
    resource: { id: '/tmp/notes.txt' },
    agent: { trust_tier: 2, enabled: true, suspended: false, allowed_tools: ['Read'] },
    delegation: { depth: 0, max_action_tier: 1, classification_caps: {}, purpose: 'testing' },
  }
  return JSON.stringify(req, null, 2)
}

function LegRow({ label, leg }: { label: string; leg: PolicyTestLeg }) {
  return (
    <div className="mb-2">
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="w-44 shrink-0 text-sm font-medium">{label}</span>
        <Badge tone={leg.effect === 'allow' ? 'good' : 'warn'}>{leg.effect}</Badge>
        <span className="text-sm text-muted-foreground">{leg.reason}</span>
      </div>
      {leg.source || leg.policy_id ? (
        <div className="pl-[11.5rem] text-xs text-muted-foreground">
          {leg.source ? `source: ${leg.source}` : null}
          {leg.source && leg.policy_id ? ' — ' : null}
          {leg.policy_id ? `policy ${leg.policy_id}` : null}
        </div>
      ) : null}
    </div>
  )
}

/** Both legs, side by side, with the divergence between them called out
 *  explicitly rather than left for the reader to notice. A policy can be
 *  correct in isolation and still change nothing -- overridden by an
 *  existing policy, or redundant with one -- and that is the single most
 *  valuable thing this endpoint reports. */
function TestResultView({ result }: { result: PolicyTestResult }) {
  const differ = result.isolated.effect !== result.with_existing_policies.effect
  const legs = result.legs_evaluated
  return (
    <div className="mt-3 rounded-md border border-border p-3">
      <LegRow label="Isolated" leg={result.isolated} />
      <LegRow label="With existing policies" leg={result.with_existing_policies} />
      {differ ? (
        <p className="mt-2 text-sm text-destructive">
          ⚠ These differ: alone this policy would {result.isolated.effect}, but folded in with
          this tenant's existing policies the request would {result.with_existing_policies.effect}.
        </p>
      ) : null}
      <p className="mt-2 text-xs text-muted-foreground">
        Tier: {actionTier(result.tier.value)} ({result.tier.source}). Legs evaluated: principal
        {legs.principal ? '' : ' (not run)'}, agent{legs.agent ? '' : ' (not run)'}, delegation
        {legs.delegation ? '' : ' (not run)'} — a leg that did not run is a leg this test input
        did not exercise.
      </p>
    </div>
  )
}

/** Collapsed behind a Test button so the panel never sends a request the
 *  operator has not chosen to send. The textarea is reseeded from the
 *  current draft every time it is opened. */
function TestPanel({ language, policyContent }: { language: string; policyContent: string }) {
  const [open, setOpen] = useState(false)
  const [reqText, setReqText] = useState('')
  const [result, setResult] = useState<PolicyTestResult | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (!open) {
    return (
      <div className="mt-4 border-t border-border pt-4">
        <Button
          variant="outline"
          onClick={() => {
            setReqText(blankTestRequest(language, policyContent))
            setResult(null)
            setTestError(null)
            setOpen(true)
          }}
        >
          Test
        </Button>
      </div>
    )
  }

  const run = () => {
    setTestError(null)
    setResult(null)
    let parsed: PolicyTestRequest
    try {
      parsed = JSON.parse(reqText) as PolicyTestRequest
    } catch {
      setTestError('the request is not valid JSON')
      return
    }
    setBusy(true)
    api.testPolicy(parsed).then(
      (r) => { setResult(r); setBusy(false) },
      (err: unknown) => { setTestError(describeError(err)); setBusy(false) },
    )
  }

  return (
    <section className="mt-4 border-t border-border pt-4">
      <h4 className="mb-1 text-sm font-semibold">Test</h4>
      <p className="mb-3 text-xs text-muted-foreground">
        A complete policy.test request. Edit any dimension to probe how this candidate would
        evaluate against it.
      </p>
      <Field label="Request" htmlFor="test-request"
        hint={"A simulated authorization request. Nothing is stored and no policy changes — edit any field and run it again."}
      >
        <Textarea id="test-request" value={reqText} onChange={(e) => setReqText(e.target.value)} />
      </Field>
      <div className="flex gap-2">
        <Button onClick={run} disabled={busy}>Run test</Button>
        <Button variant="ghost" onClick={() => setOpen(false)}>Close</Button>
      </div>
      {testError ? <ErrorBanner>{testError}</ErrorBanner> : null}
      {result ? <TestResultView result={result} /> : null}
    </section>
  )
}

/** The form body plus Validate and Test. A separate component, keyed by
 *  editingID in the caller, so validation/test state resets whenever a
 *  different policy (or a fresh New policy) is opened rather than carrying
 *  a stale verdict across sessions. */
function PolicyForm({ editor, languages }: { editor: Editor<Policy>; languages: string[] }) {
  const draft = editor.draft
  const [validation, setValidation] = useState<string | null>(null)
  if (draft === null) return null

  return (
    <>
      <Field label="Name" htmlFor="name"
        hint={"Required, and unique within this tenant."}
      >
        <TextInput id="name" value={draft.name} onChange={(e) => editor.patch({ name: e.target.value })} />
      </Field>
      <Field label="Description" htmlFor="description"
        hint={"Free text for other operators. The PDP never reads it."}
      >
        <TextInput
          id="description"
          value={draft.description}
          onChange={(e) => editor.patch({ description: e.target.value })}
        />
      </Field>
      <Field label="Language" htmlFor="language"
        hint={"The engine that evaluates this policy. This list is what this build actually registers."}
      >
        <Select
          id="language"
          options={languages}
          value={draft.language}
          onChange={(e) => {
            const language = e.target.value
            // The store refuses anything but multiValuedLanguageEffect for a
            // language whose engine cannot declare an effect, so switching
            // pins the value rather than carrying the previous language's
            // choice into a guaranteed refusal.
            editor.patch(declaresEffect(language) ? { language } : { language, effect: 'deny' })
          }}
        />
      </Field>

      {declaresEffect(draft.language) ? (
        <Field label="Effect" htmlFor="effect"
          hint="Checked against what the policy text declares; a disagreement is refused.">
          <Select id="effect" options={['allow', 'deny']} value={draft.effect}
            onChange={(e) => editor.patch({ effect: e.target.value })} />
        </Field>
      ) : (
        <p className="mb-3 text-xs text-muted-foreground">
          A {draft.language} policy can define rules of both effects, resolved only when a
          request is evaluated. The stored effect is a fixed placeholder for this language and is
          not yours to choose.
        </p>
      )}

      <Checkbox
        id="enabled"
        label="Enabled"
        checked={draft.enabled}
        onChange={(e) => editor.patch({ enabled: e.target.checked })}
      />

      <Field label="Policy content" htmlFor="policy_content"
        hint={"The policy source. Validate runs it through the real engine before you save, and a save the engine rejects is refused."}
      >
        <Textarea
          id="policy_content"
          value={draft.policy_content}
          onChange={(e) => editor.patch({ policy_content: e.target.value })}
        />
      </Field>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Button
          variant="outline"
          onClick={() => {
            setValidation(null)
            api.validatePolicy(draft.language, draft.policy_content).then(
              () => setValidation('valid'),
              (err: unknown) => setValidation(describeError(err)),
            )
          }}
        >
          Validate
        </Button>
        {validation === 'valid' ? <Badge tone="good">valid</Badge> : null}
      </div>
      {validation !== null && validation !== 'valid' ? <ErrorBanner>{validation}</ErrorBanner> : null}

      <div className="mt-4 flex gap-2">
        <Button onClick={editor.save} disabled={editor.busy}>Save</Button>
        <Button variant="outline" onClick={editor.close}>Cancel</Button>
      </div>

      <TestPanel language={draft.language} policyContent={draft.policy_content} />
    </>
  )
}

export function PoliciesScreen() {
  const { rows, error, reload } = useList<Policy>(api.policies)
  const [confirming, setConfirming] = useState<Policy | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [removing, setRemoving] = useState<string | null>(null)

  const [languages, setLanguages] = useState<string[]>([])
  const [languagesLoaded, setLanguagesLoaded] = useState(false)
  useEffect(() => {
    let live = true
    api.policyLanguages().then(
      (ls) => { if (live) { setLanguages(ls); setLanguagesLoaded(true) } },
      () => { if (live) { setLanguages([]); setLanguagesLoaded(true) } },
    )
    return () => { live = false }
  }, [])
  const firstLanguage = languages[0]

  const res = useMemo(() => ({
    get: api.policy,
    create: api.createPolicy,
    update: api.updatePolicy,
    onSaved: reload,
  }), [reload])
  const editor = useEditor<Policy>(res)

  const remove = useCallback((p: Policy) => {
    setRemoving(p.id)
    api.deletePolicy(p.id).then(
      () => { setConfirming(null); setActionError(null); setRemoving(null); reload() },
      (err: unknown) => { setConfirming(null); setActionError(describeError(err)); setRemoving(null) },
    )
  }, [reload])

  if (editor.draft !== null) {
    return (
      <Panel title={editor.editingID === null ? 'New policy' : 'Edit policy'} onClose={editor.close}>
        {editor.error ? <ErrorBanner>{editor.error}</ErrorBanner> : null}
        <PolicyForm key={editor.editingID ?? 'new'} editor={editor} languages={languages} />
      </Panel>
    )
  }

  return (
    <section>
      <ScreenHeader title="Policies">
        A policy's effect is shown only for the two languages where the stored value is
        checked against the policy text at write time. A Rego or XACML policy can define
        rules of both effects, resolved only when a request is evaluated, so no effect is
        claimed for one.
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
            prompt={`Delete policy ${confirming.name}?`}
            confirmLabel="Delete policy"
            busyLabel="Deleting…"
            busy={removing === confirming.id}
            onConfirm={() => remove(confirming)}
            onCancel={() => setConfirming(null)}
          />
        </div>
      ) : null}

      <div className="mb-3">
        {!languagesLoaded ? (
          <Loading />
        ) : firstLanguage === undefined ? (
          <p className="text-sm text-muted-foreground">
            This build has no policy engines registered, so policies cannot be authored here.
          </p>
        ) : (
          <Button onClick={() => editor.create({ ...BLANK, language: firstLanguage })}>New policy</Button>
        )}
      </div>

      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Name', 'Language', 'Effect', 'Version', 'Enabled', 'Updated', '']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={7}>No policies.</EmptyRow> : null}
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
                  <TCell className="text-right">
                    <Button variant="ghost" size="sm" onClick={() => editor.edit(p.id)}>Edit</Button>
                    <Button variant="ghost" size="sm" onClick={() => setConfirming(p)}>Delete</Button>
                  </TCell>
                </TRow>
              )
            })}
          </tbody>
        </Table>
      )}
    </section>
  )
}
