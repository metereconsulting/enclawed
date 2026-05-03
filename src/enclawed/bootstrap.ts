// One-call activation. Called from src/entry.ts at the top of the main-module
// branch, before any plugin or transit module has been imported. Always on.
// Behavior:
//   1. Optionally asserts that Node is in FIPS mode (config-controlled).
//   2. Installs the egress-guard fetch wrapper.
//   3. Opens the hash-chained audit log.
//   4. Registers the runtime on a globalThis symbol so other patches see it.
//   5. Appends a single "enclawed.boot" record.

import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";

import { AuditLogger } from "./audit-log.js";
import {
  type ClassificationScheme,
  loadSchemeByName,
  setActiveScheme,
} from "./classification-scheme.js";
import { assertFipsMode } from "./crypto-fips.js";
import { installEgressGuard } from "./egress-guard.js";
import { type Flavor, getFlavor } from "./flavor.js";
import { type ModuleVerificationMap, preloadModuleDecisions } from "./integration/preload.js";
import { defaultEnclavedPolicy, defaultOpenPolicy, type Policy } from "./policy.js";
import { type EnclawedRuntime, setRuntime } from "./runtime.js";
import { lockTrustRoot } from "./trust-root.js";

export type BootstrapOptions = {
  flavor?: Flavor;
  policy?: Policy;
  auditPath?: string;
  fipsRequired?: boolean;
  env?: NodeJS.ProcessEnv;
  modulesRoot?: string;        // path to the modules dir; defaults to "extensions"
  preloadModules?: boolean;    // default true; set false in tests
  classificationScheme?: ClassificationScheme;  // overrides any env-driven loader
};

const DEFAULT_AUDIT_PATH = "/var/log/enclawed/audit.jsonl";

export async function bootstrapEnclawed(opts: BootstrapOptions = {}): Promise<EnclawedRuntime> {
  const env = opts.env ?? process.env;
  const flavor = opts.flavor ?? getFlavor(env);

  // Classification scheme: explicit opts > ENCLAWED_CLASSIFICATION_SCHEME
  // (built-in id OR file path to a custom scheme JSON) > the default scheme.
  // The choice is applied to the global active-scheme registry before any
  // module manifests are parsed, so manifest clearance validation uses the
  // chosen vocabulary.
  let activeSchemeId = "enclawed-default";
  if (opts.classificationScheme) {
    setActiveScheme(opts.classificationScheme);
    activeSchemeId = opts.classificationScheme.id;
  } else if (env.ENCLAWED_CLASSIFICATION_SCHEME) {
    const scheme = await loadSchemeByName(env.ENCLAWED_CLASSIFICATION_SCHEME);
    setActiveScheme(scheme);
    activeSchemeId = scheme.id;
  }

  // FIPS is required by default in the enclaved flavor. In the open flavor
  // the default is OFF (community deployments rarely have a FIPS-validated
  // OpenSSL build). Explicit ENCLAWED_FIPS_REQUIRED overrides either way.
  const fipsDefault = flavor === "enclaved";
  const fipsEnv = env.ENCLAWED_FIPS_REQUIRED;
  const fipsRequired =
    opts.fipsRequired ?? (fipsEnv === undefined ? fipsDefault : fipsEnv !== "0");
  if (fipsRequired) {
    assertFipsMode();
  }

  const policy = opts.policy ?? (flavor === "enclaved" ? defaultEnclavedPolicy() : defaultOpenPolicy());
  const auditPath = opts.auditPath ?? env.ENCLAWED_AUDIT_PATH ?? DEFAULT_AUDIT_PATH;
  await mkdir(dirname(auditPath), { recursive: true }).catch(() => {
    // Best-effort: the dir may already exist or be on read-only media in tests.
  });
  const audit = new AuditLogger({ filePath: auditPath });

  const restoreFetch = installEgressGuard({
    allowedHosts: policy.allowedHosts,
    // In the enclaved flavor we permanently bind globalThis.fetch to the
    // guard so module code cannot reassign it to bypass egress control.
    freeze: flavor === "enclaved",
    onDeny: ({ host }) => {
      audit
        .append({ type: "egress.deny", actor: "process", level: null, payload: { host } })
        .catch(() => {});
    },
  });

  // In the enclaved flavor, lock the trust root after this point. Any module
  // code attempting setTrustRoot() / resetTrustRoot() after bootstrap will
  // throw TrustRootLockedError. The deploying organization should call
  // setTrustRoot(orgOwnedSigners) BEFORE invoking bootstrapEnclawed().
  if (flavor === "enclaved") {
    lockTrustRoot();
  }

  let moduleDecisions: ModuleVerificationMap | null = null;
  if (opts.preloadModules !== false) {
    try {
      moduleDecisions = await preloadModuleDecisions(opts.modulesRoot);
    } catch (e) {
      // Preload failure in enclaved mode is fatal (we cannot vouch for any
      // module if we cannot read the manifest tree). In open mode it falls
      // back to permissive — log only.
      if (flavor === "enclaved") throw e;
      moduleDecisions = new Map();
    }
  }

  const runtime: EnclawedRuntime = Object.freeze({
    flavor,
    policy,
    audit,
    restoreFetch,
    fipsRequired,
    moduleDecisions,
  });
  setRuntime(runtime);

  await audit.append({
    type: "enclawed.boot",
    actor: "process",
    level: null,
    payload: {
      pid: process.pid,
      flavor,
      classificationScheme: activeSchemeId,
      enforceAllowlists: policy.enforceAllowlists,
      allowedChannels: [...policy.allowedChannels],
      allowedProviders: [...policy.allowedProviders],
      allowedHosts: [...policy.allowedHosts],
      fipsRequired,
    },
  });

  return runtime;
}
