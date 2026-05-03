// Schema for `enclawed.module.json` — the per-module manifest that sits
// alongside `package.json` inside every loadable module directory. The
// manifest is canonicalized + SHA-256 hashed; the hash is signed with a
// key listed in the trust root (see trust-root.ts). In the "enclaved"
// flavor an unsigned or untrusted manifest causes the module to be
// rejected before any of its code is imported.

import { createHash } from "node:crypto";

// Manifest clearance is a free-form string; validation is delegated to the
// active classification scheme (see classification-scheme.ts). The string
// must match a canonical name or alias of a level in the active scheme,
// case-insensitively. Built-in presets cover generic industry, US-gov,
// healthcare, and financial-services vocabularies; deploying organizations
// can also ship their own scheme as JSON. The legacy hardcoded list below
// is kept ONLY as a fallback for callers that bypass the active scheme.
import { clearanceNameToRank as schemeNameToRank } from "./classification-scheme.js";

export type ClearanceLevel = string;

// Legacy list retained for callers that look up a string clearance without
// going through the active scheme. The active scheme is the source of
// truth at runtime.
export const LEGACY_CLEARANCE_ORDER: Record<string, number> = {
  // Generic
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
  "restricted-plus": 4,
  // US-government aliases
  unclassified: 0,
  cui: 1,
  secret: 3,
  "top-secret": 4,
  "q-cleared": 4,
};

// Backwards-compatible export name for code that read the old constant.
export const CLEARANCE_ORDER = LEGACY_CLEARANCE_ORDER;

export function clearanceToRank(name: string): number | undefined {
  const fromScheme = schemeNameToRank(name);
  if (fromScheme !== undefined) return fromScheme;
  return LEGACY_CLEARANCE_ORDER[name.toLowerCase()];
}

export type ModuleManifest = Readonly<{
  v: 1;
  id: string;            // module identity, must equal directory name
  publisher: string;     // human-readable publisher (e.g. "OpenClaw Inc.")
  version: string;       // semver of the module
  clearance: ClearanceLevel;
  capabilities: ReadonlyArray<string>;  // e.g. ["channel", "provider", "tool", "mcp-client"]
  signerKeyId?: string;  // identifier of the key in trust-root that signed this manifest
  signature?: string;    // base64 Ed25519 signature over canonicalManifestHash()
}>;

export function parseManifest(raw: unknown): ModuleManifest {
  if (raw === null || typeof raw !== "object") {
    throw new TypeError("manifest must be a JSON object");
  }
  const m = raw as Record<string, unknown>;
  if (m.v !== 1) throw new Error(`unsupported manifest version: ${String(m.v)}`);
  const id = String(m.id ?? "").trim();
  if (!id) throw new Error("manifest.id is required");
  const publisher = String(m.publisher ?? "").trim();
  if (!publisher) throw new Error("manifest.publisher is required");
  const version = String(m.version ?? "").trim();
  if (!version) throw new Error("manifest.version is required");
  const clearance = String(m.clearance ?? "").trim() as ClearanceLevel;
  if (clearanceToRank(clearance) === undefined) {
    throw new Error(
      `manifest.clearance "${clearance}" is not a recognized name in the active classification scheme`,
    );
  }
  const capsIn = m.capabilities;
  if (!Array.isArray(capsIn) || !capsIn.every((c) => typeof c === "string")) {
    throw new Error("manifest.capabilities must be string[]");
  }
  const capabilities = Object.freeze(capsIn.slice() as string[]);
  const signerKeyId =
    typeof m.signerKeyId === "string" && m.signerKeyId.trim().length > 0
      ? m.signerKeyId.trim()
      : undefined;
  const signature =
    typeof m.signature === "string" && m.signature.trim().length > 0
      ? m.signature.trim()
      : undefined;
  return Object.freeze({ v: 1, id, publisher, version, clearance, capabilities, signerKeyId, signature });
}

// Canonical bytes that get hashed + signed. Excludes the signature itself so
// the same manifest body produces a stable hash regardless of whether it has
// been signed yet.
export function canonicalManifestBytes(manifest: ModuleManifest): Buffer {
  const body = {
    v: manifest.v,
    id: manifest.id,
    publisher: manifest.publisher,
    version: manifest.version,
    clearance: manifest.clearance,
    capabilities: [...manifest.capabilities].sort(),
    signerKeyId: manifest.signerKeyId ?? null,
  };
  // Sort keys for stable serialization.
  return Buffer.from(canonicalize(body), "utf8");
}

export function canonicalManifestHash(manifest: ModuleManifest): string {
  return createHash("sha256").update(canonicalManifestBytes(manifest)).digest("hex");
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
}

export function meetsClearance(actual: ClearanceLevel, required: ClearanceLevel): boolean {
  return CLEARANCE_ORDER[actual] >= CLEARANCE_ORDER[required];
}
