import { getNative, type NativeIdentity } from "./native.js";
import type { IdentityRecord, MintOptions } from "./types.js";

/**
 * Cryptographic identity for an agent.
 *
 * Two factory paths:
 *
 * ```ts
 * // Deterministic — same inputs always produce the same keypair.
 * const id = AgentIdentity.derive("research-bot", "phd-lab");
 *
 * // From the encrypted vault.
 * const id = AgentIdentity.fromVault({
 *   fingerprint: "ag:sha256:7f3a...",
 *   password: "...",
 * });
 * ```
 *
 * The secret key is held in a private field (`#secretKey`) and never
 * appears in `JSON.stringify`, `console.log`, or `toJSON()` output.
 */
export class AgentIdentity {
  readonly name: string;
  readonly project: string;
  /** Hex-encoded 32-byte Ed25519 public key. */
  readonly publicKey: string;
  /** `ag:sha256:<16-hex-chars>`. */
  readonly fingerprint: string;

  #secretKey: string;

  private constructor(rec: IdentityRecord) {
    this.name = rec.name;
    this.project = rec.project;
    this.publicKey = rec.publicKey;
    this.fingerprint = rec.fingerprint;
    this.#secretKey = rec.secretKey;
  }

  /**
   * Deterministically derive an identity from `(name, project, seed?)`.
   *
   * The same inputs always produce the same Ed25519 keypair (HKDF-SHA256).
   * Pass a random `seed` to mint an ephemeral identity that's still bound
   * to a name/project for logging.
   */
  static derive(
    name: string,
    project: string,
    seed?: Uint8Array,
  ): AgentIdentity {
    const rec = getNative().deriveIdentity(
      name,
      project,
      seed ? Buffer.from(seed) : undefined,
    );
    return new AgentIdentity(rec);
  }

  /**
   * Reconstruct an identity from a raw hex-encoded 32-byte secret key.
   * Use with care — prefer `derive()` or `fromVault()`.
   */
  static fromSecretKey(
    name: string,
    project: string,
    secretKeyHex: string,
  ): AgentIdentity {
    const native = getNative();
    // Derive the public key by round-tripping through the Rust core.
    const pubKeyBuf = native.mintToken(name, project, secretKeyHex, [], 60, 0);
    const parsed = native.parseToken(pubKeyBuf);
    return new AgentIdentity({
      name,
      project,
      publicKey: parsed.issuer,
      fingerprint: parsed.fingerprint,
      secretKey: secretKeyHex,
    });
  }

  /**
   * Internal factory used by the vault module. Not part of the public API.
   * @internal
   */
  static _fromNative(rec: NativeIdentity): AgentIdentity {
    return new AgentIdentity(rec);
  }

  /**
   * Mint a compact binary token signed by this identity.
   *
   * Returns a `Uint8Array` (~170-180 bytes). Transmit it as-is, or
   * base64-encode for text channels.
   */
  mintToken(opts: MintOptions = {}): Uint8Array {
    const buf = getNative().mintToken(
      this.name,
      this.project,
      this.#secretKey,
      [...(opts.scopes ?? [])],
      opts.ttlSeconds ?? 900,
      opts.maxCalls ?? 0,
    );
    return new Uint8Array(buf);
  }

  /**
   * Export the hex-encoded secret key. Handle with the same care as a
   * private SSH key.
   */
  exportSecretKey(): string {
    return this.#secretKey;
  }

  /** Safe serialisation — secret key is never included. */
  toJSON(): Omit<IdentityRecord, "secretKey"> {
    return {
      name: this.name,
      project: this.project,
      publicKey: this.publicKey,
      fingerprint: this.fingerprint,
    };
  }

  /** Debug-friendly string representation (no secrets). */
  toString(): string {
    return `AgentIdentity(${this.name}@${this.project} ${this.fingerprint})`;
  }
}
