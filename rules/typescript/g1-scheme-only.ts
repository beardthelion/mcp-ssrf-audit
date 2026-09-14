// Semgrep test fixture for mcp-ssrf-audit-g1-typescript.
// G1 = the guard checks only the URL scheme (protocol allowlist or
// scheme prefix) and never inspects the host or its addresses.
// The finding lands on the scheme-check expression (the guard site).

// Positive: the fetcher-mcp / CVE-2026-26118 shape. A standalone validator
// that parses the URL, checks the protocol allowlist, and returns.
const ALLOWED_PROTOCOLS = ["http:", "https:"];

export function validateUrlProtocol(url: string): string {
  const trimmedUrl = url.trim();
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(trimmedUrl);
  } catch {
    throw new Error("invalid URL");
  }
  // ruleid: mcp-ssrf-audit-g1-typescript
  if (!ALLOWED_PROTOCOLS.includes(parsedUrl.protocol)) {
    throw new Error(`protocol ${parsedUrl.protocol} is not allowed`);
  }
  return trimmedUrl;
}

// Positive: inline scheme check inside a tool handler. The handler input is
// not the taint source here; the rule flags the weak check itself.
declare const server: any;

server.registerTool("read", {}, async (args: { url: string }) => {
  const u = new URL(args.url);
  // ruleid: mcp-ssrf-audit-g1-typescript
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("bad scheme");
  }
  return fetch(u.toString());
});

// Positive: startsWith on the raw URL string is a scheme-only prefix check.
server.tool("grab", {}, async (args: { url: string }) => {
  // ruleid: mcp-ssrf-audit-g1-typescript
  if (!args.url.startsWith("https://")) {
    throw new Error("https only");
  }
  return fetch(args.url);
});

// Positive: Set.prototype.has on the protocol.
const ALLOWED = new Set(["http:", "https:"]);
function checkScheme(u: string) {
  const p = new URL(u);
  // ruleid: mcp-ssrf-audit-g1-typescript
  if (!ALLOWED.has(p.protocol)) return false;
  return true;
}

// Negative: scheme check plus host-level checks in the same block is not
// scheme-only; the site classifies under the remaining guard stages (the
// bracketed-IPv6 bug below is G4, not G1).
async function isSafeUrl(input: string): Promise<boolean> {
  const u = new URL(input);
  // ok: mcp-ssrf-audit-g1-typescript
  if (!(u.protocol === "http:" || u.protocol === "https:")) {
    return false;
  }
  const hostname = u.hostname;
  if (net.isIP(hostname) === 4 && isPrivateIPv4(hostname)) return false;
  const ips = await dns.promises.lookup(hostname, { all: true });
  return ips.every((r) => !isPrivateIPv4(r.address));
}

// Negative: zcaceres shape. Protocol check plus bracket-stripped hostname
// passed to a range library; nothing scheme-only remains.
function validateUrl(url: string): void {
  const parsedUrl = new URL(url);
  // ok: mcp-ssrf-audit-g1-typescript
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error("blocked protocol");
  }
  const hostname = parsedUrl.hostname;
  const bare = hostname.startsWith("[") ? hostname.slice(1, -1) : hostname;
  if (bare === "localhost" || is_ip_private(bare)) throw new Error("private");
}

// Negative: an unrelated function that merely reads .protocol (no check
// expression) is not a guard.
function describe(u: string) {
  const p = new URL(u);
  return `scheme was ${p.protocol}`;
}

// Negative: a scheme check inside a schema-refinement callback is an
// input-shape check, not the fetch-path guard (the kazuph zod refine shape).
declare const z: any;
const FetchArgsSchema = z.object({
  url: z
    .string()
    .url()
    .refine((val: string) => {
      try {
        const u = new URL(val);
        // ok: mcp-ssrf-audit-g1-typescript
        return u.protocol === "http:" || u.protocol === "https:";
      } catch {
        return false;
      }
    }),
});
