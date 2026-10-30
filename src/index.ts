/**
 * d1-field-crypto — AES-256-GCM field-level encryption for Cloudflare D1 Workers apps.
 *
 * Blob wire format v2 (base64-encoded), written by `encryptField`:
 *   [0x00] [format: 0x02] [key version: 1 byte] [iv: 12 bytes] [ciphertext + GCM auth tag]
 * The GCM associated data is the 3-byte header plus the encoded `FieldContext`, so a blob only
 * decrypts under the table/column/row it was written for.
 *
 * LEGACY v1 format (read-only, no associated data):
 *   [key version: 1 byte] [iv: 12 bytes] [ciphertext + GCM auth tag]
 * Key versions are 1–255, so a leading 0x00 always means a versioned (v2+) blob.
 *
 * Key management: supply a JSON keyring {"1": "<base64-256-bit-key>", "2": "..."}.
 * The highest version number is the active encryption key; all versions can decrypt.
 */

const IV_SIZE = 12;
const TAG_SIZE = 16;
const FORMAT_MARKER = 0x00;
const FORMAT_V2 = 0x02;
const V2_HEADER_SIZE = 3;

/** Where a field lives. Required on every encrypt/decrypt; bound to the ciphertext as GCM AAD. */
export interface FieldContext {
  table: string;
  column: string;
  /** Stable row identifier assigned before the write (e.g. a UUID primary key). */
  row: string | number;
}

export interface DecryptOptions {
  /** Accept LEGACY v1 blobs (no context binding). Default true; set false once migrated. */
  allowLegacy?: boolean;
}

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
    // Canonical decimal only: parseInt would let "01" collide with "1" and accept "1abc".
    const version = /^[1-9][0-9]{0,2}$/.test(vStr) ? Number(vStr) : NaN;
    if (!Number.isInteger(version) || version < 1 || version > 255) {
      throw new Error(`Key version must be 1–255, got "${vStr}"`);
    }
    keys.set(version, await importAesKey(b64));
    if (version > activeVersion) activeVersion = version;
  }

  if (keys.size === 0) throw new Error("Keyring must contain at least one key");
  return { keys, activeVersion };
}

function encodeContext(context: FieldContext): Uint8Array<ArrayBuffer> {
  if (!context || typeof context !== "object") throw new Error("A FieldContext is required");
  const parts = [context.table, context.column, context.row];
  const names = ["table", "column", "row"];
  parts.forEach((p, i) => {
    if ((typeof p !== "string" && typeof p !== "number") || String(p) === "") {
      throw new Error(`FieldContext.${names[i]} must be a non-empty string or number`);
    }
  });
  return new TextEncoder().encode(JSON.stringify(parts.map(String)));
}

function associatedData(header: Uint8Array, context: FieldContext): Uint8Array<ArrayBuffer> {
  const ctx = encodeContext(context);
  const aad = new Uint8Array(header.byteLength + ctx.byteLength);
  aad.set(header);
  aad.set(ctx, header.byteLength);
  return aad;
}

function encodeBlob(bytes: Uint8Array): string {
  // Chunked: spreading a large array into fromCharCode overflows the call stack (~100 KB+).
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 0x8000) {
    binary += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + 0x8000)));
  }
  return btoa(binary);
}

function decodeBlob(encoded: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
}

/** True if `encoded` is a LEGACY v1 blob that should be re-encrypted with `encryptField`. */
export function isLegacyFormat(encoded: string): boolean {
  return decodeBlob(encoded)[0] !== FORMAT_MARKER;
}

/**
 * Encrypt a plaintext string with the active key, bound to `context`.
 * @returns  Base64-encoded v2 blob (see wire format above).
 */
export async function encryptField(
  plaintext: string,
  keyring: ResolvedKeyring,
  context: FieldContext,
): Promise<string> {
  const key = keyring.keys.get(keyring.activeVersion);
  if (!key) throw new Error(`Active key version ${keyring.activeVersion} not in keyring`);

  const header = new Uint8Array([FORMAT_MARKER, FORMAT_V2, keyring.activeVersion]);
  const additionalData = associatedData(header, context);
  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, key, encoded);

  const blob = new Uint8Array(V2_HEADER_SIZE + IV_SIZE + ciphertext.byteLength);
  blob.set(header);
  blob.set(iv, V2_HEADER_SIZE);
  blob.set(new Uint8Array(ciphertext), V2_HEADER_SIZE + IV_SIZE);

  return encodeBlob(blob);
}

/**
 * Decrypt a base64 blob produced by `encryptField`, using the same `context` it was written with.
 * Selects the key version stored in the blob. LEGACY v1 blobs decrypt without context binding
 * unless `allowLegacy` is false.
 */
export async function decryptField(
  encoded: string,
  keyring: ResolvedKeyring,
  context: FieldContext,
  options: DecryptOptions = {},
): Promise<string> {
  const blob = decodeBlob(encoded);
  let version: number;
  let offset: number;
  let additionalData: Uint8Array<ArrayBuffer> | undefined;

  if (blob[0] === FORMAT_MARKER) {
    if (blob[1] !== FORMAT_V2) throw new Error(`Unsupported blob format ${blob[1]}`);
    version = blob[2];
    offset = V2_HEADER_SIZE;
    additionalData = associatedData(blob.slice(0, V2_HEADER_SIZE), context);
  } else {
    // LEGACY v1 format: no associated data. Kept so existing rows can be read and migrated.
    if (options.allowLegacy === false) throw new Error("Legacy v1 blob rejected (allowLegacy: false)");
    encodeContext(context);
    version = blob[0];
    offset = 1;
  }

  if (blob.byteLength < offset + IV_SIZE + TAG_SIZE) {
    throw new Error("Blob too short to be a valid encrypted field");
  }
  const iv = blob.slice(offset, offset + IV_SIZE);
  const ciphertext = blob.slice(offset + IV_SIZE);

  const key = keyring.keys.get(version);
  if (!key) throw new Error(`Key version ${version} not found in keyring`);

  const params: AesGcmParams = additionalData ? { name: "AES-GCM", iv, additionalData } : { name: "AES-GCM", iv };
  const plaintext = await crypto.subtle.decrypt(params, key, ciphertext);
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

/** Which column a v2 blind index belongs to. Bound into the HMAC input for domain separation. */
export interface IndexDomain {
  table: string;
  column: string;
  /** Version of the index key, recorded in the output so rows show which key produced them. Default 1. */
  keyVersion?: number;
}

const BIDX_V2_TAG = "d1fc-bidx-v2";

/** The v2 blind-index normaliser: trim, lowercase, Unicode NFC. Use it to compare decrypted values. */
export function normalizeIndexValue(value: string): string {
  return value.trim().toLowerCase().normalize("NFC");
}

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Length-prefix each part (4-byte big-endian) so no two (table, column, value) triples collide. */
function encodeIndexInput(parts: string[]): Uint8Array<ArrayBuffer> {
  const encoded = parts.map((p) => new TextEncoder().encode(p));
  const out = new Uint8Array(encoded.reduce((n, e) => n + 4 + e.byteLength, 0));
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const e of encoded) {
    view.setUint32(offset, e.byteLength);
    out.set(e, offset + 4);
    offset += 4 + e.byteLength;
  }
  return out;
}

/**
 * Compute a deterministic HMAC-SHA256 blind index for lookup / UNIQUE enforcement.
 * Store this alongside the encrypted field; query with `WHERE email_bidx = ?`.
 *
 * Without `domain` (LEGACY, unchanged): normalises with lowercase + trim and returns 64 hex chars.
 * Equal values collide across columns sharing an index key, and NFC/NFD variants differ.
 *
 * With `domain` (v2, recommended): binds table and column into the HMAC input, normalises with
 * `normalizeIndexValue` (adds Unicode NFC) and returns `bi2.<keyVersion>.<64 hex>`.
 * v2 output never equals legacy output; see the README for migrating stored indexes.
 */
export async function blindIndex(value: string, indexKey: CryptoKey, domain?: IndexDomain): Promise<string> {
  if (domain === undefined) {
    const encoded = new TextEncoder().encode(value.toLowerCase().trim());
    return toHex(await crypto.subtle.sign("HMAC", indexKey, encoded));
  }

  const { table, column, keyVersion = 1 } = domain;
  for (const [name, p] of [["table", table], ["column", column]] as const) {
    if (typeof p !== "string" || p === "") throw new Error(`IndexDomain.${name} must be a non-empty string`);
  }
  if (!Number.isInteger(keyVersion) || keyVersion < 1 || keyVersion > 255) {
    throw new Error(`IndexDomain.keyVersion must be 1–255, got ${keyVersion}`);
  }
  const input = encodeIndexInput([BIDX_V2_TAG, table, column, normalizeIndexValue(value)]);
  return `bi2.${keyVersion}.${toHex(await crypto.subtle.sign("HMAC", indexKey, input))}`;
}
