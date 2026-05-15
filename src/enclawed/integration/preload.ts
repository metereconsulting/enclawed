// Boot-time module manifest pre-verification.
//
// Walks the modules root directory, parses every `enclawed.module.json` it
// finds, runs each through checkModule() against the active flavor + trust
// root, and returns the decisions keyed by module id. The bootstrap stashes
// the resulting Map on the runtime singleton so the synchronous plugin
// validation chokepoints (channel-validation, provider-validation) can
// query the verified state without doing async I/O on a hot path.

import { readdir } from "node:fs/promises";
import { join } from "node:path";

import type { ModuleDecision } from "../module-loader.js";
import { loadModuleManifest, verifyModuleAtPath } from "./module-loader-shim.js";

export const DEFAULT_MODULES_ROOT = "extensions";

export type ModuleVerificationMap = ReadonlyMap<string, ModuleDecision>;

export async function preloadModuleDecisions(
  rootDir: string = DEFAULT_MODULES_ROOT,
): Promise<ModuleVerificationMap> {
  const out = new Map<string, ModuleDecision>();
  let entries: Array<{ name: string; isDirectory(): boolean }>;
  try {
    entries = await readdir(rootDir, { withFileTypes: true });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return out;
    throw e;
  }
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const moduleDir = join(rootDir, ent.name);
    try {
      const decision = await verifyModuleAtPath(moduleDir);
      // Index by manifest.id when present (so downstream lookup matches the
      // plugin id the registry will use), else by directory name.
      let key = ent.name;
      const manifest = await loadModuleManifest(moduleDir);
      if (manifest) key = manifest.id;
      out.set(key, decision);
    } catch (e) {
      out.set(ent.name, {
        allowed: false,
        flavor: "enclaved",
        reason: `manifest parse error: ${(e as Error).message}`,
      });
    }
  }
  return out;
}
