import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from './api'

// vi.mock, not vi.spyOn: api.ts binds authHeader at import time, so replacing
// the property on the module namespace afterwards does not affect the caller.
vi.mock('./auth', () => ({
  authHeader: () => ({ Authorization: 'Bearer t' }),
  onUnauthorized: () => {},
}))

function okJSON(value: unknown) {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  }))
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('request', () => {
  it('serialises the body and declares its content type', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON({ id: 'r1' }))

    await api.createResourceLabelRule({
      id: '', tenant_id: '', prefix: '/secret-', hierarchy: 'nato', level: 'SECRET',
    })

    expect(f).toHaveBeenCalledTimes(1)
    const [path, init] = f.mock.calls[0] as [string, RequestInit]
    expect(path).toBe('/v1/resource-label-rules')
    expect(init.method).toBe('POST')
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
    // The whole body, not merely "a body": a form that drops a field is the
    // failure this suite exists to catch.
    expect(JSON.parse(init.body as string)).toEqual({
      id: '', tenant_id: '', prefix: '/secret-', hierarchy: 'nato', level: 'SECRET',
    })
  })

  it('sends no body and no content type on a GET', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON([]))

    await api.resourceLabelRules()

    const [, init] = f.mock.calls[0] as [string, RequestInit]
    expect(init.body).toBeUndefined()
    expect((init.headers as Record<string, string>)['Content-Type']).toBeUndefined()
  })

  it('carries an empty prefix to the wire rather than dropping it', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON({ id: 'r2' }))

    await api.createResourceLabelRule({
      id: '', tenant_id: '', prefix: '', hierarchy: 'nato', level: 'PUBLIC',
    })

    // "" is R7's tenant-wide catch-all. A helper that pruned empty strings
    // would silently turn the catch-all into a rule matching nothing.
    const [, init] = f.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(init.body as string).prefix).toBe('')
  })

  it('sends the policy source as policy_content, the field the server reads', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON({ valid: true }))

    await api.validatePolicy('cedar', 'permit(principal, action, resource);')

    // validatePolicyRequest.Text is tagged json:"policy_content" (validate.go).
    // Sending "text" leaves it empty and validates an EMPTY policy instead.
    const [, init] = f.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(init.body as string)).toEqual({
      language: 'cedar', policy_content: 'permit(principal, action, resource);',
    })
  })

  it('wraps caps in the envelope the server decodes', async () => {
    const f = vi.spyOn(globalThis, 'fetch')
      .mockReturnValue(okJSON({ agent_id: 'a', classification_caps: {}, catch_all: {} }))

    await api.putAgentCaps('a1', { nato: 'SECRET' })

    // capsRequest is {"classification_caps": {...}} (agent_caps.go). A bare
    // map decodes to nil and CLEARS every cap -- widening a ceiling while
    // reporting success.
    const [, init] = f.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(init.body as string)).toEqual({ classification_caps: { nato: 'SECRET' } })
  })

  it('does not send the uncovered override unless asked', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON({}))
    await api.putAgentCaps('a1', { nato: 'SECRET' })
    // The flag is an acknowledgement gate on a security control. A default
    // that carries it would defeat the gate for every write, and the screen
    // tests -- which assert arguments, not the URL -- would stay green.
    const call = f.mock.calls[0]
    if (call === undefined) throw new Error('fetch was not called')
    expect(call[0]).toBe('/v1/agents/a1/classification-caps')
  })

  it('sends the uncovered override only when explicitly asked', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockReturnValue(okJSON({}))
    await api.putAgentCaps('a1', { nato: 'SECRET' }, true)
    const call = f.mock.calls[0]
    if (call === undefined) throw new Error('fetch was not called')
    expect(call[0]).toBe('/v1/agents/a1/classification-caps?allow_uncovered=true')
  })
})
