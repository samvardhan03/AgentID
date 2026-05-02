/**
 * Public identity record. The `secretKey` field is hex-encoded sensitive
 * material — never log, serialise, or transmit it across untrusted channels.
 */
export interface IdentityRecord {
  readonly name: string;
  readonly project: string;
  /** Hex-encoded 32-byte Ed25519 public key. */
  readonly publicKey: string;
  /** Short fingerprint: `ag:sha256:<16-hex-chars>`. */
  readonly fingerprint: string;
  /** Hex-encoded 32-byte Ed25519 secret key. SENSITIVE. */
  readonly secretKey: string;
}

/** Decoded token claims — returned by both `parseToken` and `verifyToken`. */
export interface TokenClaims {
  readonly name: string;
  readonly project: string;
  readonly scopes: readonly string[];
  /** Unix seconds. */
  readonly issuedAt: number;
  /** Unix seconds. */
  readonly expiresAt: number;
  /** Per-token call quota. 0 = unlimited. */
  readonly maxCalls: number;
  /** Random per-token nonce (16 hex chars). */
  readonly tokenId: string;
  /** Hex-encoded 32-byte issuer public key. */
  readonly issuer: string;
  /** Issuer fingerprint: `ag:sha256:<16-hex>`. */
  readonly fingerprint: string;
}

/**
 * Result of a non-throwing verification attempt.
 *
 * `ok: true`  → `claims` is present; signature and expiry are valid.
 * `ok: false` → `error` describes what failed.
 */
export type VerifyResult =
  | { readonly ok: true; readonly claims: TokenClaims }
  | { readonly ok: false; readonly error: string };

/** Public metadata for a vault-stored identity. Safe to log. */
export interface VaultEntry {
  readonly name: string;
  readonly project: string;
  readonly fingerprint: string;
  /** Hex-encoded public key. */
  readonly publicKey: string;
  /** Unix seconds. */
  readonly createdAt: number;
}

/** Options for {@link AgentIdentity.mintToken}. */
export interface MintOptions {
  /** Scopes embedded in the token (e.g. `["read:arxiv", "write:notes"]`). */
  readonly scopes?: readonly string[];
  /** Token time-to-live in seconds. Default: 900 (15 min). Max: 86 400 (24 h). */
  readonly ttlSeconds?: number;
  /** Per-token call quota. Default: 0 (unlimited). */
  readonly maxCalls?: number;
}
