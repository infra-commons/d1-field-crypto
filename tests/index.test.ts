import { describe, it, expect } from "vitest";
import {
  resolveKeyring,
  encryptField,
  decryptField,
  importIndexKey,
  blindIndex,
  normalizeIndexValue,
  isLegacyFormat,
  type FieldContext,
  type KeyringRaw,
} from "../src/index.js";

// 32 random bytes encoded as base64 (deterministic for tests)
const KEY_V1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 32 zero bytes
const KEY_V2 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="; // 32 one bytes
const INDEX_KEY = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="; // 32 two bytes
const CTX: FieldContext = { table: "users", column: "email_enc", row: "u-1" };

const bytes = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));

/** Build a LEGACY v1 blob exactly as the pre-v2 encoder did (no associated data). */
async function legacyBlob(plaintext: string, keyB64: string, version: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", bytes(keyB64), { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext)));
  return b64(new Uint8Array([version, ...iv, ...ct]));
}

describe("resolveKeyring", () => {
  it("parses a single-version keyring and sets activeVersion", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    expect(kr.activeVersion).toBe(1);
    expect(kr.keys.size).toBe(1);
  });

  it("picks the highest version as active", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1, "2": KEY_V2 });
    expect(kr.activeVersion).toBe(2);
    expect(kr.keys.size).toBe(2);
  });

  it("rejects an empty keyring", async () => {
    await expect(resolveKeyring({} as KeyringRaw)).rejects.toThrow("at least one key");
  });

  it("rejects a key that is not 32 bytes", async () => {
    const shortKey = btoa("tooshort");
    await expect(resolveKeyring({ "1": shortKey })).rejects.toThrow("32 bytes");
  });

  it("rejects out-of-range version numbers", async () => {
    await expect(resolveKeyring({ "0": KEY_V1 })).rejects.toThrow("1–255");
    await expect(resolveKeyring({ "256": KEY_V1 })).rejects.toThrow("1–255");
  });
});

describe("encryptField / decryptField", () => {
  it("round-trips a plaintext string", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const blob = await encryptField("hello@example.com", kr, CTX);
    const result = await decryptField(blob, kr, CTX);
    expect(result).toBe("hello@example.com");
  });

  it("produces different ciphertexts for the same plaintext (random IV)", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const b1 = await encryptField("same", kr, CTX);
    const b2 = await encryptField("same", kr, CTX);
    expect(b1).not.toBe(b2);
  });

  it("writes the v2 header: marker 0x00, format 2, key version", async () => {
    const kr = await resolveKeyring({ "2": KEY_V2 });
    const blob = bytes(await encryptField("test", kr, CTX));
    expect([blob[0], blob[1], blob[2]]).toEqual([0, 2, 2]);
    expect(isLegacyFormat(b64(blob))).toBe(false);
  });

  it("decrypts a v1 blob after key rotation to v2", async () => {
    const kr1 = await resolveKeyring({ "1": KEY_V1 });
    const blob = await encryptField("sensitive", kr1, CTX);

    // Simulate rotation: add v2 — old v1 blob should still decrypt
    const kr2 = await resolveKeyring({ "1": KEY_V1, "2": KEY_V2 });
    const result = await decryptField(blob, kr2, CTX);
    expect(result).toBe("sensitive");
  });

  it("new encrypts with the active (higher) version after rotation", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1, "2": KEY_V2 });
    const blob = await encryptField("post-rotation", kr, CTX);
    expect(bytes(blob)[2]).toBe(2); // active = v2
  });

  it("throws when decrypting with a keyring missing the blob's key version", async () => {
    const kr1 = await resolveKeyring({ "1": KEY_V1 });
    const blob = await encryptField("x", kr1, CTX);

    const kr2 = await resolveKeyring({ "2": KEY_V2 }); // v1 removed
    await expect(decryptField(blob, kr2, CTX)).rejects.toThrow("version 1");
  });

  it("throws on a tampered (too-short) blob", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    await expect(decryptField(btoa("short"), kr, CTX)).rejects.toThrow("too short");
  });

  it("round-trips unicode and multi-line text", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const text = "田中\nコーチメモ: 体重 65.2kg\n🏋️";
    expect(await decryptField(await encryptField(text, kr, CTX), kr, CTX)).toBe(text);
  });

  it("round-trips an empty string", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    expect(await decryptField(await encryptField("", kr, CTX), kr, CTX)).toBe("");
  });
});

describe("context binding", () => {
  it("round-trips with a numeric row id", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const ctx = { table: "users", column: "ssn_enc", row: 42 };
    expect(await decryptField(await encryptField("123-45-6789", kr, ctx), kr, ctx)).toBe("123-45-6789");
  });

  it.each([
    ["row", { ...CTX, row: "u-2" }],
    ["column", { ...CTX, column: "name_enc" }],
    ["table", { ...CTX, table: "admins" }],
  ])("rejects a blob decrypted under the wrong %s", async (_, wrong) => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const blob = await encryptField("secret", kr, CTX);
    await expect(decryptField(blob, kr, wrong)).rejects.toThrow();
  });

  it("does not let context parts run together", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const blob = await encryptField("x", kr, { table: "a|b", column: "c", row: 1 });
    await expect(decryptField(blob, kr, { table: "a", column: "b|c", row: 1 })).rejects.toThrow();
  });

  it("requires a complete context", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    await expect(encryptField("x", kr, { ...CTX, row: "" })).rejects.toThrow("FieldContext.row");
    // @ts-expect-error — untyped callers must fail closed
    await expect(encryptField("x", kr)).rejects.toThrow("FieldContext");
    const blob = await encryptField("x", kr, CTX);
    // @ts-expect-error — missing column
    await expect(decryptField(blob, kr, { table: "users", row: 1 })).rejects.toThrow("FieldContext.column");
  });

  it("rejects an unknown format version", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const blob = bytes(await encryptField("x", kr, CTX));
    blob[1] = 3;
    await expect(decryptField(b64(blob), kr, CTX)).rejects.toThrow("Unsupported blob format 3");
  });

  it("does not decrypt a v2 blob with its header stripped (no downgrade to legacy)", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const stripped = b64(bytes(await encryptField("x", kr, CTX)).slice(2));
    expect(isLegacyFormat(stripped)).toBe(true);
    await expect(decryptField(stripped, kr, CTX)).rejects.toThrow();
  });

  it("does not put key material or plaintext in errors", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const blob = await encryptField("plain-secret", kr, CTX);
    const err = await decryptField(blob, kr, { ...CTX, row: "u-9" }).catch((e: Error) => e);
    expect(String(err)).not.toContain("plain-secret");
    expect(String(err)).not.toContain(KEY_V1);
  });
});

describe("LEGACY v1 blobs", () => {
  it("still decrypt, under any context, and report isLegacyFormat", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1, "2": KEY_V2 });
    const old = await legacyBlob("legacy@example.com", KEY_V1, 1);
    expect(isLegacyFormat(old)).toBe(true);
    expect(await decryptField(old, kr, CTX)).toBe("legacy@example.com");
  });

  it("migrate by re-encrypting to v2", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const old = await legacyBlob("migrate-me", KEY_V1, 1);
    const fresh = await encryptField(await decryptField(old, kr, CTX), kr, CTX);
    expect(isLegacyFormat(fresh)).toBe(false);
    expect(await decryptField(fresh, kr, CTX, { allowLegacy: false })).toBe("migrate-me");
  });

  it("are rejected when allowLegacy is false", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const old = await legacyBlob("x", KEY_V1, 1);
    await expect(decryptField(old, kr, CTX, { allowLegacy: false })).rejects.toThrow("allowLegacy");
  });
});

describe("blindIndex", () => {
  it("returns a 64-char lowercase hex string", async () => {
    const key = await importIndexKey(INDEX_KEY);
    const idx = await blindIndex("hello@example.com", key);
    expect(idx).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for the same input", async () => {
    const key = await importIndexKey(INDEX_KEY);
    const a = await blindIndex("test@example.com", key);
    const b = await blindIndex("test@example.com", key);
    expect(a).toBe(b);
  });

  it("normalises case and whitespace before hashing", async () => {
    const key = await importIndexKey(INDEX_KEY);
    const a = await blindIndex("User@Example.COM", key);
    const b = await blindIndex("  user@example.com  ", key);
    expect(a).toBe(b);
  });

  it("produces different indices for different values", async () => {
    const key = await importIndexKey(INDEX_KEY);
    const a = await blindIndex("alice@example.com", key);
    const b = await blindIndex("bob@example.com", key);
    expect(a).not.toBe(b);
  });

  it("produces different indices for different index keys", async () => {
    const keyA = await importIndexKey(INDEX_KEY);
    const keyB = await importIndexKey(KEY_V1);
    const a = await blindIndex("same@example.com", keyA);
    const b = await blindIndex("same@example.com", keyB);
    expect(a).not.toBe(b);
  });

  it("rejects a non-32-byte index key", async () => {
    await expect(importIndexKey(btoa("tooshort"))).rejects.toThrow("32 bytes");
  });

  it("keeps the legacy output byte-identical (no domain)", async () => {
    // HMAC-SHA256(32 × 0x02, "hello@example.com"), computed independently with node:crypto.
    const key = await importIndexKey(INDEX_KEY);
    expect(await blindIndex("  Hello@Example.com ", key)).toBe(
      "e4dad59b1696613f786f57a065f872f707ac044d6fdc88376de8f799fc0d8288",
    );
  });
});

describe("blindIndex v2 (with domain)", () => {
  const EMAIL = { table: "users", column: "email_bidx" };

  it("returns bi2.<keyVersion>.<64 hex>, never the legacy value", async () => {
    const key = await importIndexKey(INDEX_KEY);
    const v2 = await blindIndex("hello@example.com", key, EMAIL);
    expect(v2).toMatch(/^bi2\.1\.[0-9a-f]{64}$/);
    expect(v2.slice(6)).not.toBe(await blindIndex("hello@example.com", key));
    expect(await blindIndex("hello@example.com", key, { ...EMAIL, keyVersion: 7 })).toBe(`bi2.7.${v2.slice(6)}`);
  });

  it("separates columns and tables that share an index key", async () => {
    const key = await importIndexKey(INDEX_KEY);
    const a = await blindIndex("same", key, EMAIL);
    expect(await blindIndex("same", key, { table: "users", column: "phone_bidx" })).not.toBe(a);
    expect(await blindIndex("same", key, { table: "admins", column: "email_bidx" })).not.toBe(a);
  });

  it("is unambiguous across part boundaries", async () => {
    const key = await importIndexKey(INDEX_KEY);
    const a = await blindIndex("x", key, { table: "ab", column: "c" });
    const b = await blindIndex("x", key, { table: "a", column: "bc" });
    expect(a).not.toBe(b);
  });

  it("treats NFC and NFD forms, case and whitespace as equal", async () => {
    const key = await importIndexKey(INDEX_KEY);
    const nfc = "josé@example.com";
    const nfd = " JOSÉ@EXAMPLE.COM ";
    expect(nfc).not.toBe(nfd.trim().toLowerCase());
    expect(await blindIndex(nfd, key, EMAIL)).toBe(await blindIndex(nfc, key, EMAIL));
    expect(normalizeIndexValue(nfd)).toBe(nfc);
  });

  it("validates the domain", async () => {
    const key = await importIndexKey(INDEX_KEY);
    await expect(blindIndex("x", key, { table: "", column: "c" })).rejects.toThrow("table");
    await expect(blindIndex("x", key, { table: "t", column: "" })).rejects.toThrow("column");
    await expect(blindIndex("x", key, { ...EMAIL, keyVersion: 0 })).rejects.toThrow("1–255");
    await expect(blindIndex("x", key, { ...EMAIL, keyVersion: 1.5 })).rejects.toThrow("1–255");
  });
});
