import { getNative, type NativeClaims } from "./native.js";
import type { TokenClaims, VerifyResult } from "./types.js";

/**
 * Parse + cryptographically verify a token.
 *
 * Checks the Ed25519 signature, expiry, and (optionally) that the issuer
 * matches `expectedPublicKey`. Throws on any failure.
 *
 * Verification is offline and takes <0.1 ms.
 *
 * @param token            Raw token bytes (the output of `AgentIdentity.mintToken()`).
 * @param expectedPublicKey  Optional hex-encoded 32-byte issuer pubkey. If
 *   provided, the token's embedded issuer must match exactly.
 */
export function verifyToken(
  token: Uint8Array,
  expectedPublicKey?: string,
): TokenClaims {
  const raw = getNative().verifyToken(
    Buffer.from(token),
    expectedPublicKey ?? null,
  );
  return normaliseClaims(raw);
}

/**
 * Non-throwing verification. Returns `{ ok: true, claims }` on success,
 * `{ ok: false, error }` on any failure.
 */
export function tryVerifyToken(
  token: Uint8Array,
  expectedPublicKey?: string,
): VerifyResult {
  try {
    return { ok: true, claims: verifyToken(token, expectedPublicKey) };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Parse a token without verifying its signature or expiry.
 *
 * Useful for debugging and logging. **Never** trust the result for
 * authorization — use {@link verifyToken} instead.
 */
export function parseToken(token: Uint8Array): TokenClaims {
  const raw = getNative().parseToken(Buffer.from(token));
  return normaliseClaims(raw);
}

/** BigInt → Number for i64 timestamps. Safe for unix seconds until ~year 285 000. */
function normaliseClaims(c: NativeClaims): TokenClaims {
  return {
    name: c.name,
    project: c.project,
    scopes: c.scopes,
    issuedAt: typeof c.issuedAt === "bigint" ? Number(c.issuedAt) : c.issuedAt,
    expiresAt:
      typeof c.expiresAt === "bigint" ? Number(c.expiresAt) : c.expiresAt,
    maxCalls: c.maxCalls,
    tokenId: c.tokenId,
    issuer: c.issuer,
    fingerprint: c.fingerprint,
  };
}
