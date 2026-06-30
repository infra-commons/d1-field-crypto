import { describe, it, expect } from "vitest";
import {
  resolveKeyring,
  encryptField,
  decryptField,
  importIndexKey,
  blindIndex,
  type KeyringRaw,
} from "../src/index.js";

// 32 random bytes encoded as base64 (deterministic for tests)
const KEY_V1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 32 zero bytes
const KEY_V2 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="; // 32 one bytes
const INDEX_KEY = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="; // 32 two bytes

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
    const blob = await encryptField("hello@example.com", kr);
    const result = await decryptField(blob, kr);
    expect(result).toBe("hello@example.com");
  });

  it("produces different ciphertexts for the same plaintext (random IV)", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const b1 = await encryptField("same", kr);
    const b2 = await encryptField("same", kr);
    expect(b1).not.toBe(b2);
  });

  it("stores the key version in byte 0 of the blob", async () => {
    const kr = await resolveKeyring({ "2": KEY_V2 });
    const blob = await encryptField("test", kr);
    const bytes = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
    expect(bytes[0]).toBe(2);
  });

  it("decrypts a v1 blob after key rotation to v2", async () => {
    const kr1 = await resolveKeyring({ "1": KEY_V1 });
    const blob = await encryptField("sensitive", kr1);

    // Simulate rotation: add v2 — old v1 blob should still decrypt
    const kr2 = await resolveKeyring({ "1": KEY_V1, "2": KEY_V2 });
    const result = await decryptField(blob, kr2);
    expect(result).toBe("sensitive");
  });

  it("new encrypts with the active (higher) version after rotation", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1, "2": KEY_V2 });
    const blob = await encryptField("post-rotation", kr);
    const bytes = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
    expect(bytes[0]).toBe(2); // active = v2
  });

  it("throws when decrypting with a keyring missing the blob's key version", async () => {
    const kr1 = await resolveKeyring({ "1": KEY_V1 });
    const blob = await encryptField("x", kr1);

    const kr2 = await resolveKeyring({ "2": KEY_V2 }); // v1 removed
    await expect(decryptField(blob, kr2)).rejects.toThrow("version 1");
  });

  it("throws on a tampered (too-short) blob", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    await expect(decryptField(btoa("short"), kr)).rejects.toThrow("too short");
  });

  it("round-trips unicode and multi-line text", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    const text = "田中\nコーチメモ: 体重 65.2kg\n🏋️";
    expect(await decryptField(await encryptField(text, kr), kr)).toBe(text);
  });

  it("round-trips an empty string", async () => {
    const kr = await resolveKeyring({ "1": KEY_V1 });
    expect(await decryptField(await encryptField("", kr), kr)).toBe("");
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
});
