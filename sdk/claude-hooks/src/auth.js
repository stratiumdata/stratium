/**
 * auth.js
 *
 * Keycloak OIDC token management for Stratium Claude hooks.
 *
 * Token storage priority (most secure to least):
 *   1. OS keychain (macOS Keychain / GNOME Keyring) — via keychain.js
 *   2. File cache at ~/.claude/stratium-tokens.json (chmod 0600) — fallback
 *
 * Expiry is checked with a 60-second buffer to allow proactive refresh.
 * No external npm dependencies.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execFileSync }   = require('child_process');
const { keycloakPasswordGrant, keycloakRefreshToken } = require('./grpc-client');
const { keychainGet, keychainSet, keychainDelete, keychainAvailable } = require('./keychain');

/** Path to the file-based token cache (fallback when keychain unavailable). */
const TOKEN_CACHE_PATH = path.join(os.homedir(), '.claude', 'stratium-tokens.json');

/** Seconds before actual expiry when we proactively refresh. */
const EXPIRY_BUFFER_SECONDS = 60;

/**
 * @typedef {object} TokenEntry
 * @property {string} access_token
 * @property {string} refresh_token
 * @property {number} expires_at      - Unix timestamp (seconds) when access token expires
 * @property {string} [user_email]    - Resolved from JWT sub/email if available
 */

/**
 * @typedef {object} TokenCache
 * @property {Record<string, TokenEntry>} tokens  - Key: `${keycloak_url}|${realm}|${username}`
 */

// ── Cache key ─────────────────────────────────────────────────────────────────

/**
 * Build a stable cache key for a user+realm combination.
 * Also used as the keychain account name.
 */
function cacheKey(keycloakUrl, realm, username) {
  return `${keycloakUrl}|${realm}|${username}`;
}

// ── OS keychain helpers ───────────────────────────────────────────────────────

/**
 * Load a token entry from the OS keychain.
 * @param {string} key
 * @returns {TokenEntry|null}
 */
function keychainLoadEntry(key) {
  try {
    const raw = keychainGet(key);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Persist a token entry to the OS keychain.
 * @param {string} key
 * @param {TokenEntry} entry
 * @returns {boolean} true if stored in keychain
 */
function keychainSaveEntry(key, entry) {
  return keychainSet(key, JSON.stringify(entry));
}

// ── File cache helpers ────────────────────────────────────────────────────────

/** @returns {TokenCache} */
function loadFileCache() {
  try {
    const raw = fs.readFileSync(TOKEN_CACHE_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return { tokens: {} };
  }
}

/** @param {TokenCache} cache */
function saveFileCache(cache) {
  const dir = path.dirname(TOKEN_CACHE_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(TOKEN_CACHE_PATH, JSON.stringify(cache, null, 2), {
    encoding: 'utf8',
    mode: 0o600,
  });
}

// ── Unified load/save (keychain preferred, file fallback) ─────────────────────

/**
 * Load a cached token entry, trying keychain first then file cache.
 * @param {string} key
 * @returns {TokenEntry|null}
 */
function loadEntry(key) {
  if (keychainAvailable()) {
    const entry = keychainLoadEntry(key);
    if (entry) return entry;
  }
  // Fall back to file cache
  const cache = loadFileCache();
  return cache.tokens[key] || null;
}

/**
 * Persist a token entry to keychain (preferred) and file cache (always, as backup).
 * @param {string} key
 * @param {TokenEntry} entry
 */
function saveEntry(key, entry) {
  // Always write to file cache as backup
  const cache = loadFileCache();
  cache.tokens[key] = entry;
  saveFileCache(cache);

  // Also attempt keychain — failure is silently ignored
  if (keychainAvailable()) {
    keychainSaveEntry(key, entry);
  }
}

/**
 * Remove a token entry from both keychain and file cache.
 * @param {string} key
 */
function deleteEntry(key) {
  if (keychainAvailable()) {
    keychainDelete(key);
  }
  const cache = loadFileCache();
  delete cache.tokens[key];
  saveFileCache(cache);
}

// ── JWT helpers ───────────────────────────────────────────────────────────────

/**
 * Decode the `exp` claim from a JWT without verifying the signature.
 * @param {string} jwt
 * @returns {number|null}
 */
function jwtExpiry(jwt) {
  try {
    const parts   = jwt.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    return typeof payload.exp === 'number' ? payload.exp : null;
  } catch {
    return null;
  }
}

/**
 * Extract the preferred_username or email from a JWT.
 * @param {string} jwt
 * @returns {string}
 */
function jwtEmail(jwt) {
  try {
    const parts   = jwt.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    return payload.email || payload.preferred_username || payload.sub || '';
  } catch {
    return '';
  }
}

// ── Token validity ────────────────────────────────────────────────────────────

/**
 * Check whether a cached token is still valid (not expired within buffer).
 * @param {TokenEntry} entry
 * @returns {boolean}
 */
function isValid(entry) {
  if (!entry || !entry.access_token) return false;
  const now = Math.floor(Date.now() / 1000);
  return entry.expires_at > now + EXPIRY_BUFFER_SECONDS;
}

// ── TTY password prompt ───────────────────────────────────────────────────────

/**
 * Prompt for a password on the controlling TTY using bash read -rs (no-echo).
 * Throws in non-TTY contexts (hook execution without env var).
 *
 * @param {string} username
 * @returns {string}
 */
function readPasswordFromTty(username) {
  if (!process.stdin.isTTY) {
    throw new Error(
      `Stratium: no cached OIDC token for ${username}. ` +
      `Set STRATIUM_OIDC_PASSWORD env var or run 'stratium-hooks login' interactively.`
    );
  }

  process.stderr.write(`Stratium: enter password for ${username}: `);

  const password = execFileSync(
    'bash',
    ['-c', 'read -rs line && printf "%s" "$line"'],
    { stdio: ['inherit', 'pipe', 'inherit'], encoding: 'utf8' }
  ).trim();

  process.stderr.write('\n');
  return password;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Get a valid access token for the given user.
 *
 * Priority:
 *   1. Valid entry in keychain or file cache — return immediately
 *   2. Expired entry with valid refresh token — silent refresh, update cache
 *   3. No valid entry — authenticate with password, cache result
 *
 * @param {object} params
 * @param {string} params.keycloak_url
 * @param {string} params.realm
 * @param {string} params.client_id
 * @param {string} params.username
 * @returns {TokenEntry}
 * @throws {Error} If authentication fails
 */
function getToken(params) {
  const { keycloak_url, realm, client_id, username } = params;
  const key   = cacheKey(keycloak_url, realm, username);
  const entry = loadEntry(key);

  // 1. Valid cached token
  if (isValid(entry)) {
    return entry;
  }

  // 2. Try silent refresh
  if (entry && entry.refresh_token) {
    try {
      const refreshed = keycloakRefreshToken({
        keycloak_url, realm, client_id,
        refresh_token: entry.refresh_token,
      });

      const exp = jwtExpiry(refreshed.access_token);
      const now = Math.floor(Date.now() / 1000);
      const newEntry = {
        access_token:  refreshed.access_token,
        refresh_token: refreshed.refresh_token || entry.refresh_token,
        expires_at:    exp || (now + (refreshed.expires_in || 300)),
        user_email:    jwtEmail(refreshed.access_token) || entry.user_email,
      };

      saveEntry(key, newEntry);
      return newEntry;
    } catch {
      // Refresh token expired — fall through to password auth
    }
  }

  // 3. Authenticate with password
  const password = process.env.STRATIUM_OIDC_PASSWORD || readPasswordFromTty(username);
  const granted  = keycloakPasswordGrant({ keycloak_url, realm, client_id, username, password });

  const exp = jwtExpiry(granted.access_token);
  const now = Math.floor(Date.now() / 1000);
  const newEntry = {
    access_token:  granted.access_token,
    refresh_token: granted.refresh_token,
    expires_at:    exp || (now + (granted.expires_in || 300)),
    user_email:    jwtEmail(granted.access_token) || username,
  };

  saveEntry(key, newEntry);
  return newEntry;
}

/**
 * Clear the cached token for a specific user (keychain + file).
 */
function clearToken(keycloakUrl, realm, username) {
  deleteEntry(cacheKey(keycloakUrl, realm, username));
}

/** Clear all cached tokens from the file cache. Keychain entries are per-key. */
function clearAllTokens() {
  // Clear file cache
  saveFileCache({ tokens: {} });
  // Note: keychain entries are cleared per-key on logout — we cannot enumerate
  // all keychain entries from this process without platform-specific APIs.
  // Individual clearToken() calls handle keychain cleanup on explicit logout.
}

module.exports = {
  getToken,
  clearToken,
  clearAllTokens,
  isValid,
  keychainAvailable,
  TOKEN_CACHE_PATH,
};
