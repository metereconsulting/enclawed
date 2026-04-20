// Network-egress allowlist. Replaces global.fetch with a wrapper that denies
// any request whose target host is not on the allowlist.
//
// LIMITATION: this guard does NOT cover (a) raw net.Socket / dgram / DNS
// traffic from native modules, (b) child processes, (c) Node http.Agent
// usage that bypasses fetch, (d) connections from sandboxed renderers.
// A real classified enclave additionally requires kernel-level egress
// controls (nftables / eBPF / network namespace), enforced at the host or
// network appliance, NOT in user-space Node code. See
// enclawed/MODIFICATIONS.md "Gaps for accreditation".

function hostOf(input) {
  // input is a Request, URL, or string.
  if (typeof input === 'string') {
    try { return new URL(input).hostname; } catch { return null; }
  }
  if (input && typeof input.url === 'string') {
    try { return new URL(input.url).hostname; } catch { return null; }
  }
  if (input && typeof input.hostname === 'string') return input.hostname;
  return null;
}

export class EgressDeniedError extends Error {
  constructor(host, reason) {
    super(`egress denied: ${host || '<unknown host>'} (${reason})`);
    this.name = 'EgressDeniedError';
    this.host = host;
    this.reason = reason;
  }
}

export function createEgressGuard({
  allowedHosts,
  fetchImpl = globalThis.fetch,
  onDeny,
}) {
  const allow = new Set((allowedHosts || []).map(String));
  if (typeof fetchImpl !== 'function') {
    throw new Error('createEgressGuard: a fetch implementation is required');
  }
  const guarded = async function guardedFetch(input, init) {
    const host = hostOf(input);
    if (!host || !allow.has(host)) {
      const err = new EgressDeniedError(host, 'host not on allowlist');
      if (typeof onDeny === 'function') {
        try { onDeny({ host, input, init }); } catch { /* swallow */ }
      }
      throw err;
    }
    return fetchImpl(input, init);
  };
  guarded.__enclawedGuard = true;
  return guarded;
}

export function installEgressGuard(opts = {}) {
  const previous = globalThis.fetch;
  const guard = createEgressGuard({ ...opts, fetchImpl: previous });
  if (opts.freeze) {
    // Make the guard non-writable + non-configurable. After this call,
    // attempting `globalThis.fetch = ...` throws in strict mode (which
    // ESM modules are by default) and silently fails in sloppy mode.
    // The returned restorer is a no-op when the property is frozen.
    Object.defineProperty(globalThis, 'fetch', {
      value: guard, writable: false, configurable: false, enumerable: true,
    });
    return () => {
      // No-op: the property is permanently bound to the guard.
    };
  }
  globalThis.fetch = guard;
  return () => { globalThis.fetch = previous; };
}
