# @infra-commons/d1-field-crypto

AES-256-GCM field-level encryption for Cloudflare D1 Workers apps.

Encrypts individual columns before writing to D1 and decrypts on read. Adds application-layer
protection on top of D1's platform-level encryption at rest — guards against leaked DB exports
and console/insider access to row contents.

## Quick start

```bash
npm install github:infra-commons/d1-field-crypto
```

```typescript
import { resolveKeyring, encryptField, decryptField, importIndexKey, blindIndex } from "@infra-commons/d1-field-crypto";

// Initialise once at Worker startup (cache the resolved keyring)
const keyring = await resolveKeyring(JSON.parse(env.D1_FIELD_KEYRING));
const emailIdxKey = await importIndexKey(env.D1_EMAIL_INDEX_KEY);
```

## Key management

### Generate keys

```bash
# Encryption key (add to keyring JSON as version "1")
openssl rand -base64 32

# Blind-index key (separate secret from encryption key)
openssl rand -base64 32
```

### Store as Worker secrets

```bash
# Keyring JSON: {"1": "<base64-256-bit-key>"}
echo '{"1":"<key>"}' | wrangler secret put D1_FIELD_KEYRING

# Blind-index key
echo '<base64-key>' | wrangler secret put D1_EMAIL_INDEX_KEY
```

### Key rotation

1. Generate a new key (version N+1).
2. Add it to the keyring JSON: `{"1":"<old>", "2":"<new>"}`.
3. Update `D1_FIELD_KEYRING` secret. New writes use v2; old v1 rows still decrypt.
4. Run the backfill migration (see below) to re-encrypt all v1 rows to v2.
5. Once backfill is complete and verified, remove v1 from the keyring.

## Encrypting fields

```typescript
// Write path
const encEmail = await encryptField(user.email, keyring);
const emailBidx = await blindIndex(user.email, emailIdxKey);

await db.prepare(
  "INSERT INTO users (email_enc, email_bidx, name_enc) VALUES (?, ?, ?)"
).bind(encEmail, emailBidx, await encryptField(user.name, keyring)).run();

// Read path
const row = await db.prepare("SELECT email_enc, name_enc FROM users WHERE email_bidx = ?")
  .bind(await blindIndex(lookupEmail, emailIdxKey))
  .first();

const email = await decryptField(row.email_enc, keyring);
const name  = await decryptField(row.name_enc, keyring);
```

## Blind index (equality lookups on encrypted columns)

AES-GCM uses a random IV per encryption, so the same value produces different ciphertexts on
every write — you cannot use `WHERE email = ?` on encrypted data. The solution is a **blind index**:
a deterministic HMAC-SHA256 of the normalised value, stored in a sibling `email_bidx` column.

- `email_bidx` should be `TEXT NOT NULL UNIQUE` — it enforces uniqueness and enables fast lookup.
- The index key must be **different** from the encryption keyring key.
- The helper normalises input (lowercase + trim) before hashing — `user@EXAMPLE.COM` and
  `user@example.com` produce the same index.

## Wire format

Each encrypted field is a base64 string:

```
[version: 1 byte] [IV: 12 bytes] [ciphertext + GCM auth tag: variable]
```

The version byte enables key rotation: the helper reads the version from the blob and selects the
matching key from the keyring automatically.

## What NOT to encrypt

- **Token hashes** (`magic_links.token_hash`, `sessions.token_hash`): already one-way hashed.
  Encrypting them adds no security and breaks the constant-time comparison pattern.
- **Foreign keys / IDs**: encrypting join columns breaks queries.

## Schema migration pattern

Phase the migration to avoid downtime:

**Phase A — dual-write (deploy first, safe to roll back):**
- Add `email_enc TEXT`, `email_bidx TEXT UNIQUE` columns alongside existing `email TEXT UNIQUE`.
- On write: encrypt into `email_enc` + compute `email_bidx`; also write plaintext `email` (dual-write).
- On read: prefer `email_enc` if populated, fall back to `email`.
- Deploy and verify.

**Phase B — backfill (Kevin-gated, run manually):**
```bash
# Export a backup first
wrangler d1 export <DB_NAME> --remote --output backup-$(date +%Y%m%d).sql

# Run the backfill script (see migrations/backfill-encrypt.ts)
wrangler d1 execute <DB_NAME> --remote --command "SELECT COUNT(*) FROM users WHERE email_enc IS NULL"
node --env-file=.dev.vars scripts/backfill-encrypt.ts
```

**Phase C — cutover (after backfill verified on preview):**
- Stop writing plaintext `email`.
- Drop the `email` column (or keep as `NULL` for a migration period).

## API

```typescript
// Parse and import a raw keyring object (call once; cache the result)
resolveKeyring(raw: Record<string, string>): Promise<ResolvedKeyring>

// Encrypt a UTF-8 string with the active key; returns a base64 blob
encryptField(plaintext: string, keyring: ResolvedKeyring): Promise<string>

// Decrypt a base64 blob; auto-selects the key version stored in the blob
decryptField(encoded: string, keyring: ResolvedKeyring): Promise<string>

// Import a 256-bit HMAC key for blind-index use
importIndexKey(base64Key: string): Promise<CryptoKey>

// Compute a deterministic HMAC-SHA256 blind index (normalised: lowercase+trim)
blindIndex(value: string, indexKey: CryptoKey): Promise<string>
```
