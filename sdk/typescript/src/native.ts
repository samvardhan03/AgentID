/**
 * Native addon loader.
 *
 * Attempts to load the compiled Rust `.node` artifact from a short list of
 * known paths. If the binary is missing, throws a human-readable error
 * explaining exactly where it looked and how to build it.
 */

import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ---- internal native shapes (mirrors napi_bindings.rs) ----

export interface NativeIdentity {
  name: string;
  project: string;
  publicKey: string;
  fingerprint: string;
  secretKey: string;
}

export interface NativeClaims {
  name: string;
  project: string;
  scopes: string[];
  issuedAt: bigint | number;
  expiresAt: bigint | number;
  maxCalls: number;
  tokenId: string;
  issuer: string;
  fingerprint: string;
}

export interface NativeVaultEntry {
  name: string;
  project: string;
  fingerprint: string;
  publicKey: string;
  createdAt: bigint | number;
}

export interface NativeBindings {
  version(): string;
  fingerprintFromPublicKeyHex(publicKeyHex: string): string;
  deriveIdentity(
    name: string,
    project: string,
    seed?: Buffer | Uint8Array,
  ): NativeIdentity;
  mintToken(
    name: string,
    project: string,
    secretKeyHex: string,
    scopes: string[],
    ttlSeconds: number,
    maxCalls: number,
  ): Buffer;
  parseToken(token: Buffer | Uint8Array): NativeClaims;
  verifyToken(
    token: Buffer | Uint8Array,
    expectedPubkeyHex: string | null,
  ): NativeClaims;
  vaultDefaultRoot(): string;
  vaultInit(root: string): void;
  vaultList(root: string): NativeVaultEntry[];
  vaultStore(
    root: string,
    name: string,
    project: string,
    seedHex: string | null,
    password: string,
  ): NativeVaultEntry;
  vaultLoadSecretHex(
    root: string,
    fingerprint: string,
    password: string,
  ): NativeIdentity;
  vaultRemove(root: string, fingerprint: string): void;
}

// ---- resolution ----

const sdkSrcDir = dirname(fileURLToPath(import.meta.url));
const sdkRoot = resolve(sdkSrcDir, "..");
const repoRoot = resolve(sdkRoot, "..", "..");

const triple = `${process.platform}-${process.arch}`;

function candidatePaths(): string[] {
  const paths: string[] = [];

  // env override — highest priority
  const envPath = process.env["AGENTID_NATIVE_PATH"];
  if (envPath) paths.push(envPath);

  // packaged location (after build:native)
  paths.push(join(sdkRoot, "native", `agentid-core.${triple}.node`));
  paths.push(join(sdkRoot, "native", "agentid-core.node"));

  // directly from cargo output (dev convenience)
  for (const profile of ["release", "debug"]) {
    const base = join(repoRoot, "core", "target", profile);
    // napi-rs on macOS produces .dylib, Linux .so, Windows .dll
    // Node require() can load any of these if renamed to .node
    paths.push(join(base, `agentid_core.${triple}.node`));
    paths.push(join(base, "agentid_core.node"));
  }

  return paths;
}

const nodeRequire = createRequire(import.meta.url);

function loadNative(): NativeBindings {
  const paths = candidatePaths();

  for (const p of paths) {
    if (existsSync(p)) {
      try {
        return nodeRequire(p) as NativeBindings;
      } catch {
        // try next candidate
      }
    }
  }

  const lines = [
    ``,
    `[agentid] Native binary not found for platform "${triple}".`,
    ``,
    `Searched:`,
    ...paths.map((p) => `  ${p}`),
    ``,
    `To build it:`,
    ``,
    `  # From the agentid repo root:`,
    `  cd sdk/typescript && npm run build:native`,
    ``,
    `  # Or manually:`,
    `  cd core`,
    `  cargo build --release --features napi-bindings`,
    `  # Then rename the cdylib:`,
    `  cp target/release/libagentid_core.dylib \\`,
    `     ../sdk/typescript/native/agentid-core.${triple}.node`,
    ``,
    `Set AGENTID_NATIVE_PATH to point to a pre-built .node file`,
    `to override the default search paths.`,
    ``,
  ];

  throw new Error(lines.join("\n"));
}

// Eagerly load — fail fast with a clear message.
let cached: NativeBindings | undefined;

export function getNative(): NativeBindings {
  if (!cached) {
    cached = loadNative();
  }
  return cached;
}
