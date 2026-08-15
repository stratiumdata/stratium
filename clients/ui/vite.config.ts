/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// outDir points INTO the Go module, at cmd/stratium-pap/dist, because
// //go:embed cannot reach outside its own package directory — a path
// containing ".." is a compile error, not a warning. So either the embed
// directive names a directory here (impossible) or the build writes there
// (this). One build step, one artifact, no copy to forget.
//
// That directory is covered by the repo root .gitignore's bare `dist/`
// pattern, which matches at any depth, and it must stay that way: a
// committed build output would make the Go-side embed test (ui_test.go)
// pass forever regardless of whether anyone rebuilt the UI, which is the
// only thing that test exists to detect.
//
// emptyOutDir must be stated explicitly. Vite refuses to clear an outDir
// outside its own root without it, warning instead — which would leave last
// build's hashed bundles beside this one's, growing the embedded filesystem
// on every build with assets index.html no longer references.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: '../../services/cmd/stratium-pap/dist',
    emptyOutDir: true,
    rollupOptions: {
      // Two entry points, not one. callback.html is the OIDC redirect target
      // the sign-in popup lands on; it must be a real, separately-served page
      // so the popup does not boot a second copy of the whole admin app just
      // to hand back an authorization code (see src/auth.ts's header).
      // Relative to Vite's own root (this directory) — no node:path and no
      // @types/node needed for two filenames.
      input: { main: 'index.html', callback: 'callback.html' },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
  },
})
