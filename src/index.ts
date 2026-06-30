/**
 * d1-field-crypto — AES-256-GCM field-level encryption for Cloudflare D1 Workers apps.
 *
 * Blob wire format (base64-encoded):
 *   [version: 1 byte] [iv: 12 bytes] [ciphertext + GCM auth tag: variable]
 *
 * Key management: supply a JSON keyring {"1": "<base64-256-bit-key>", "2": "..."}.
 * The highest version number is the active encryption key; all versions can decrypt.
 */

const IV_SIZE = 12;

/** Raw keyring as stored in a Worker secret: version number → base64-encoded 256-bit key. */
export type KeyringRaw = Record<string, string>;

export interface ResolvedKeyring {
  keys: Map<number, CryptoKey>;
  activeVersion: number;
}

async function importAesKey(base64Key: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
  if (raw.byteLength !== 32) throw new Error(`AES-256 key must be 32 bytes, got ${raw.byteLength}`);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/**
 * Parse and import a raw keyring object (call once at startup and cache the result).
 * @param raw  Object with version strings as keys and base64-encoded 256-bit AES keys as values.
 */
export async function resolveKeyring(raw: KeyringRaw): Promise<ResolvedKeyring> {
  const keys = new Map<number, CryptoKey>();
  let activeVersion = 0;

  for (const [vStr, b64] of Object.entries(raw)) {
    const version = parseInt(vStr, 10);
    if (!Number.isInteger(version) || version < 1 || version > 255) {
      throw new Error(`Key version must be 1–255, got "${vStr}"`);
    }
    keys.set(version, await importAesKey(b64));
    if (version > activeVersion) activeVersion = version;
  }

  if (keys.size === 0) throw new Error("Keyring must contain at least one key");
  return { keys, activeVersion };
}

/**
 * Encrypt a plaintext string with the active key in the keyring.
 * @returns  Base64-encoded blob: [version(1)] [iv(12)] [ciphertext+tag]
 */
export async function encryptField(plaintext: string, keyring: ResolvedKeyring): Promise<string> {
  const key = keyring.keys.get(keyring.activeVersion);
  if (!key) throw new Error(`Active key version ${keyring.activeVersion} not in keyring`);

  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);

  const blob = new Uint8Array(1 + IV_SIZE + ciphertext.byteLength);
  blob[0] = keyring.activeVersion;
  blob.set(iv, 1);
  blob.set(new Uint8Array(ciphertext), 1 + IV_SIZE);

  return btoa(String.fromCharCode(...blob));
}

/**
 * Decrypt a base64 blob produced by `encryptField`.
 * Looks up the key version stored in the blob — supports any version in the keyring.
 */
export async function decryptField(encoded: string, keyring: ResolvedKeyring): Promise<string> {
  const blob = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
  if (blob.byteLength < 1 + IV_SIZE + 16) {
    throw new Error("Blob too short to be a valid encrypted field");
  }

  const version = blob[0];
  const iv = blob.slice(1, 1 + IV_SIZE);
  const ciphertext = blob.slice(1 + IV_SIZE);

  const key = keyring.keys.get(version);
  if (!key) throw new Error(`Key version ${version} not found in keyring`);

  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

// ── Blind index ──────────────────────────────────────────────────────────────

/**
 * Import a 256-bit key for use with `blindIndex`.
 * The index key must be DISTINCT from the encryption keyring key.
 * @param base64Key  Base64-encoded 32-byte key (generate: `openssl rand -base64 32`).
 */
export async function importIndexKey(base64Key: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
  if (raw.byteLength !== 32) throw new Error(`HMAC key must be 32 bytes, got ${raw.byteLength}`);
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

/**
 * Compute a deterministic HMAC-SHA256 blind index for lookup / UNIQUE enforcement.
 * Normalises the value (lowercase + trim) before hashing.
 * Store this alongside the encrypted field; query with `WHERE email_bidx = ?`.
 * @returns  Lowercase hex string (64 chars).
 */
export async function blindIndex(value: string, indexKey: CryptoKey): Promise<string> {
  const encoded = new TextEncoder().encode(value.toLowerCase().trim());
  const sig = await crypto.subtle.sign("HMAC", indexKey, encoded);
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
