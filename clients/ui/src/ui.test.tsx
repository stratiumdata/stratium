import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ConfirmRow, StringListInput } from './ui'

describe('StringListInput', () => {
  // allowed_tools is a []string and an EMPTY list means unrestricted, for both
  // Agent and Delegation (models.Agent.HasTool). A control that cannot express
  // the empty list cannot express "unrestricted".
  it('emits an empty array when every entry is cleared', () => {
    const onChange = vi.fn()
    render(<StringListInput value={['Read']} onChange={onChange} />)

    fireEvent.change(screen.getByDisplayValue('Read'), { target: { value: '' } })

    expect(onChange).toHaveBeenCalledWith([])
  })

  it('splits on newlines and trims, dropping blank lines but not order', () => {
    const onChange = vi.fn()
    render(<StringListInput value={[]} onChange={onChange} />)

    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'Read\n  Grep  \n\nGlob' } })

    expect(onChange).toHaveBeenCalledWith(['Read', 'Grep', 'Glob'])
  })
})

describe('ConfirmRow', () => {
  // Never window.confirm: it blocks the event loop and cannot carry the
  // resource-specific warning some deletions need.
  it('calls onConfirm only when the confirm control is pressed', () => {
    const onConfirm = vi.fn()
    const onCancel = vi.fn()
    render(
      <ConfirmRow prompt="Delete this rule?" confirmLabel="Delete" onConfirm={onConfirm} onCancel={onCancel} />,
    )

    screen.getByRole('button', { name: 'Cancel' }).click()
    expect(onCancel).toHaveBeenCalledTimes(1)
    expect(onConfirm).not.toHaveBeenCalled()

    screen.getByRole('button', { name: 'Delete' }).click()
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })
})
