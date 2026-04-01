/**
 * keychain.js
 *
 * OS-native credential storage for Stratium OIDC tokens.
 *
 * Platform support:
 *   macOS  — `security` CLI (Keychain Services)
 *   Linux  — `secret-tool` CLI (libsecret / GNOME Keyring)
 *   Other  — no-op (caller falls back to file cache)
 *
 * Tokens are stored as JSON strings in the keychain under:
 *   service: "stratium-claude-hooks"
 *   account: "<keycloak_url>|<realm>|<username>"
 *
 * No external npm dependencies.
 */

'use strict';

const { execFileSync } = require('child_process');

const SERVICE_NAME = 'stratium-claude-hooks';

/**
 * Detect which keychain CLI is available on this platform.
 *
 * @returns {'macos' | 'linux' | null}
 */
function detectPlatform() {
  if (process.platform === 'darwin') {
    try {
      // `security list-keychains` exits 0 on any macOS with Keychain available.
      // `security --version` is not a valid subcommand and exits 2, so avoid it.
      execFileSync('security', ['list-keychains'], { stdio: 'pipe', timeout: 2000 });
      return 'macos';
    } catch {
      return null;
    }
  }

  if (process.platform === 'linux') {
    try {
      execFileSync('secret-tool', ['--version'], { stdio: 'pipe', timeout: 2000 });
      return 'linux';
    } catch {
      return null;
    }
  }

  return null;
}

// Cache platform detection result — checked once per process
let _platform;
function getPlatform() {
  if (_platform === undefined) _platform = detectPlatform();
  return _platform;
}

/**
 * Store a value in the OS keychain.
 *
 * @param {string} account - Cache key (keycloak_url|realm|username)
 * @param {string} value   - JSON string to store
 * @returns {boolean} true if stored successfully
 */
function keychainSet(account, value) {
  const platform = getPlatform();

  try {
    if (platform === 'macos') {
      // Delete existing entry first (add fails if it exists)
      try {
        execFileSync('security', [
          'delete-generic-password',
          '-s', SERVICE_NAME,
          '-a', account,
        ], { stdio: 'pipe', timeout: 5000 });
      } catch {
        // Ignore — entry may not exist
      }

      execFileSync('security', [
        'add-generic-password',
        '-s', SERVICE_NAME,
        '-a', account,
        '-w', value,
        '-U',  // Update if exists (belt-and-suspenders)
      ], { stdio: 'pipe', timeout: 5000 });
      return true;
    }

    if (platform === 'linux') {
      // secret-tool store reads password from stdin
      execFileSync('secret-tool', [
        'store',
        '--label', `${SERVICE_NAME}:${account}`,
        'service', SERVICE_NAME,
        'account', account,
      ], {
        input: value,
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 5000,
      });
      return true;
    }
  } catch {
    // Keychain write failure — caller will use file cache
  }

  return false;
}

/**
 * Retrieve a value from the OS keychain.
 *
 * @param {string} account - Cache key
 * @returns {string|null} Stored value, or null if not found
 */
function keychainGet(account) {
  const platform = getPlatform();

  try {
    if (platform === 'macos') {
      const result = execFileSync('security', [
        'find-generic-password',
        '-s', SERVICE_NAME,
        '-a', account,
        '-w',  // Print password only
      ], { stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000, encoding: 'utf8' });
      return result.trim() || null;
    }

    if (platform === 'linux') {
      const result = execFileSync('secret-tool', [
        'lookup',
        'service', SERVICE_NAME,
        'account', account,
      ], { stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000, encoding: 'utf8' });
      return result.trim() || null;
    }
  } catch {
    // Not found or keychain unavailable
  }

  return null;
}

/**
 * Delete a value from the OS keychain.
 *
 * @param {string} account - Cache key
 * @returns {boolean} true if deleted successfully
 */
function keychainDelete(account) {
  const platform = getPlatform();

  try {
    if (platform === 'macos') {
      execFileSync('security', [
        'delete-generic-password',
        '-s', SERVICE_NAME,
        '-a', account,
      ], { stdio: 'pipe', timeout: 5000 });
      return true;
    }

    if (platform === 'linux') {
      execFileSync('secret-tool', [
        'clear',
        'service', SERVICE_NAME,
        'account', account,
      ], { stdio: 'pipe', timeout: 5000 });
      return true;
    }
  } catch {
    // Ignore
  }

  return false;
}

/**
 * Check whether a keychain backend is available on this machine.
 * Used by `stratium-hooks status` to report keychain integration status.
 *
 * @returns {boolean}
 */
function keychainAvailable() {
  return getPlatform() !== null;
}

module.exports = { keychainSet, keychainGet, keychainDelete, keychainAvailable };
