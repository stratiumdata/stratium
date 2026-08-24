import '@testing-library/jest-dom/vitest'

// jsdom implements <dialog> as an element but not its modal behaviour:
// showModal and close are simply absent, so ui.tsx's Modal throws on mount.
// This supplies the parts the tests actually assert on -- `open` reflecting
// state, and a `close` event on dismissal, including Escape.
//
// What it deliberately does NOT model is the reason <dialog> was chosen over
// a styled div in the first place: focus trapping, the rest of the page going
// inert, and ::backdrop. No test here can prove any of those, and a passing
// suite must not be read as evidence of them -- they were confirmed by
// driving the real console in a browser.
if (typeof HTMLDialogElement !== 'undefined' && !HTMLDialogElement.prototype.showModal) {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.open = true
    // Escape dismissal is the browser's, not the component's, so the shim
    // owns it too -- otherwise Modal's onClose contract looks untested.
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        this.close()
      }
    }
    this.addEventListener('close', () => document.removeEventListener('keydown', onKey), { once: true })
    document.addEventListener('keydown', onKey)
  }

  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.open = false
    this.dispatchEvent(new Event('close'))
  }
}
