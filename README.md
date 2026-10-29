# @infra-commons/d1-field-crypto

AES-256-GCM field-level encryption for Cloudflare D1 Workers apps.

Encrypts individual columns before writing to D1 and decrypts on read. Adds application-layer
protection on top of D1's platform-level encryption at rest — guards against leaked DB exports
and console/insider access to row contents.

## Threat model

The attacker can read **and write** D1 rows (leaked export, console access, SQL injection in the
app, a leaked API token) but does not hold the keyring. Every ciphertext is bound to a
`FieldContext` — `{ table, column, row }` — as AES-GCM associated data, so a value only decrypts
in the cell it was written to. Copying a ciphertext into another row, column or table makes
decryption fail instead of returning another user's data.

Not covered: replaying an **older** value of the same cell (rollback), and anything an attacker can
do with the keyring itself.

## Quick start

```bash
npm install github:infra-commons/d1-field-crypto
```

```typescript
import { resolveKeyring, encryptField, decryptField, importIndexKey, blindIndex, normalizeIndexValue } from "@infra-commons/d1-field-crypto";

// Initialise once at Worker startup (cache the resolved keyring)
const keyring = await resolveKeyring(JSON.parse(env.D1_FIELD_KEYRING));
const emailIdxKey = await importIndexKey(env.D1_EMAIL_INDEX_KEY);
const EMAIL_IDX = { table: "users", column: "email_bidx", keyVersion: 1 }; // v2 blind-index domain
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

Every call takes a `FieldContext` naming the table, the column and a **stable row id**. The row id
must be known before the write, so use an application-assigned primary key (e.g.
`crypto.randomUUID()`), not an `AUTOINCREMENT` id. Use the same context on read.

```typescript
// Write path
const id = crypto.randomUUID();
const ctx = (column: string) => ({ table: "users", column, row: id });

await db.prepare(
  "INSERT INTO users (id, email_enc, email_bidx, name_enc) VALUES (?, ?, ?, ?)"
).bind(
  id,
  await encryptField(user.email, keyring, ctx("email_enc")),
  await blindIndex(user.email, emailIdxKey, EMAIL_IDX),
  await encryptField(user.name, keyring, ctx("name_enc")),
).run();

// Read path
const row = await db.prepare("SELECT id, email_enc, name_enc FROM users WHERE email_bidx = ?")
  .bind(await blindIndex(lookupEmail, emailIdxKey, EMAIL_IDX))
  .first();

const email = await decryptField(row.email_enc, keyring, { table: "users", column: "email_enc", row: row.id });
const name  = await decryptField(row.name_enc, keyring, { table: "users", column: "name_enc", row: row.id });
```

## Blind index (equality lookups on encrypted columns)

AES-GCM uses a random IV per encryption, so the same value produces different ciphertexts on
every write — you cannot use `WHERE email = ?` on encrypted data. The solution is a **blind index**:
a deterministic HMAC-SHA256 of the normalised value, stored in a sibling `email_bidx` column.

- `email_bidx` should be `TEXT NOT NULL UNIQUE` — it enforces uniqueness and enables fast lookup.
- The index key must be **different** from the encryption keyring key.
- Pass an `IndexDomain` (`{ table, column, keyVersion? }`) to get a **v2** index. v2 binds
  the table and column into the HMAC, so equal values in two columns give different indexes even
  if they share a key. It also normalises with trim + lowercase + **Unicode NFC**
  (`normalizeIndexValue`), so `user@EXAMPLE.COM`, ` user@example.com ` and NFC/NFD spellings of the same
  address all produce one index. The output is `bi2.<keyVersion>.<64 hex>`. Record the index key's version
  in `keyVersion`, and stored rows then show which key produced them.
- Without a domain, `blindIndex` keeps its **legacy** behaviour byte-for-byte: lowercase + trim
  only, 64 hex chars, and no column binding. NFC/NFD variants of one address get different legacy
  indexes, which slips past `UNIQUE`. Use the legacy form only to read indexes you already stored.
- Still use a separate index key per indexed column. Domain separation is defence in depth, not a
  licence to share keys.

### Migrating stored legacy indexes to v2

v2 output never equals legacy output, so switching blindly breaks lookups on existing rows.
1. Deploy dual lookup: compute both forms, query `WHERE email_bidx IN (?, ?)` (v2, legacy), write
   v2 on every insert/update, and rewrite a matched legacy value to v2. Until the backfill
   finishes, `UNIQUE` cannot see a v2 value colliding with a legacy one, so check both forms
   before inserting.
2. Backfill: for each row still holding a 64-hex legacy value (`email_bidx NOT LIKE 'bi2.%'`),
   decrypt the field with its context and store `blindIndex(value, key, domain)`. If two rows map
   to the same v2 value, the `UNIQUE` constraint fails. That is an NFC/NFD duplicate the legacy
   index let through, and it needs a manual merge.
3. When no legacy values remain, drop the legacy half of the lookup.

The blind index is **not** bound to the row: it must be the same for equal values across rows, or
lookup is impossible. So a lookup by index only tells you which row *claims* the value. Before
acting on the match (sending a login or reset email, merging accounts), decrypt the row's field
with its own context and check it equals the normalised lookup value:

```typescript
const stored = await decryptField(row.email_enc, keyring, { table: "users", column: "email_enc", row: row.id });
if (normalizeIndexValue(stored) !== normalizeIndexValue(lookupEmail)) throw new Error("index mismatch");
// send mail to `stored`, never to the address the request supplied
```

## Wire format

Each encrypted field is a base64 string. Format v2 (all new writes):

```
[0x00] [format: 0x02] [key version: 1 byte] [IV: 12 bytes] [ciphertext + GCM auth tag]
```

The associated data is the 3-byte header followed by `JSON.stringify([table, column, String(row)])`.
The key-version byte drives rotation: the helper selects the matching key from the keyring.

**Legacy v1** (written by 1.x, read-only): `[key version] [IV] [ciphertext + tag]`, no associated
data. Key versions are 1–255, so a leading `0x00` always marks v2+. Legacy values still decrypt
(the context is validated but not bound), so they remain movable until re-encrypted.

### Migrating from 1.x

1. Upgrade and pass a context to every `encryptField` / `decryptField` call. New writes are v2.
2. Re-encrypt existing values: on read (`if (isLegacyFormat(v))` → decrypt, `encryptField` with the
   row's context, write back) and/or with a backfill over each encrypted column.
3. When `SELECT` finds no legacy values left, pass `{ allowLegacy: false }` to `decryptField` so a
   copied-in legacy value is rejected.

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

**Phase B — backfill (operator-gated, run manually):**
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

type FieldContext = { table: string; column: string; row: string | number }

// Encrypt a UTF-8 string with the active key, bound to `context`; returns a base64 v2 blob
encryptField(plaintext: string, keyring: ResolvedKeyring, context: FieldContext): Promise<string>

// Decrypt with the same context; auto-selects the key version stored in the blob.
// Legacy v1 blobs decrypt unless options.allowLegacy === false.
decryptField(encoded: string, keyring: ResolvedKeyring, context: FieldContext,
             options?: { allowLegacy?: boolean }): Promise<string>

// True if the blob is legacy v1 and should be re-encrypted
isLegacyFormat(encoded: string): boolean

// Import a 256-bit HMAC key for blind-index use
importIndexKey(base64Key: string): Promise<CryptoKey>

type IndexDomain = { table: string; column: string; keyVersion?: number }  // keyVersion 1–255, default 1

// Deterministic HMAC-SHA256 blind index.
// With domain (v2): column-bound, trim+lowercase+NFC, returns "bi2.<keyVersion>.<64 hex>".
// Without (legacy, unchanged): trim+lowercase, returns 64 hex chars.
blindIndex(value: string, indexKey: CryptoKey, domain?: IndexDomain): Promise<string>

// The v2 normaliser, for comparing a decrypted value with a lookup value
normalizeIndexValue(value: string): string
```
