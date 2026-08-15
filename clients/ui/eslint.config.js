import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist', 'node_modules'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],

      // N12, enforced by the linter and not only by review. The Go-side test
      // (services/cmd/stratium-pap/ui_test.go) scans the source tree for the
      // same identifiers; this catches it at the moment it is typed, in the
      // editor, which is cheaper than catching it in CI.
      'no-restricted-globals': [
        'error',
        { name: 'localStorage', message: 'N12: the operator token lives in memory only. No browser storage, and no fallback.' },
        { name: 'sessionStorage', message: 'N12: the operator token lives in memory only. No browser storage, and no fallback.' },
      ],
      'no-restricted-properties': [
        'error',
        { object: 'window', property: 'localStorage', message: 'N12: the operator token lives in memory only.' },
        { object: 'window', property: 'sessionStorage', message: 'N12: the operator token lives in memory only.' },
      ],
    },
  },
  {
    files: ['**/*.test.{ts,tsx}', 'src/test-setup.ts'],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    rules: {
      // Test doubles routinely assert shapes the compiler cannot see through.
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-explicit-any': 'off',

      // The N12 restriction above is lifted here, and only here: auth.test.ts
      // asserts that a full sign-in leaves both storage APIs empty, which it
      // cannot do without naming them. Test files are never bundled into
      // dist, so nothing in one can carry a token anywhere. The Go-side scan
      // (services/cmd/stratium-pap/ui_test.go) skips them for the same
      // reason.
      'no-restricted-globals': 'off',
      'no-restricted-properties': 'off',
    },
  },
  { files: ['*.config.{js,ts}'], languageOptions: { globals: globals.node } },
)
