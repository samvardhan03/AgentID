import { AgentIdentity } from "./identity.js";
import { getNative, type NativeVaultEntry } from "./native.js";
import type { VaultEntry } from "./types.js";

function normaliseEntry(n: NativeVaultEntry): VaultEntry {
  return {
    name: n.name,
    project: n.project,
    fingerprint: n.fingerprint,
    publicKey: n.publicKey,
    createdAt:
      typeof n.createdAt === "bigint" ? Number(n.createdAt) : n.createdAt,
  };
}

/**
 * Vault operations — manage encrypted identities on disk.
 *
 * The vault stores Ed25519 secret keys at `~/.agentid/keys/<fingerprint>.key`,
 * encrypted with AES-256-GCM (password-based via PBKDF2-HMAC-SHA256, 200 000
 * iterations). An unencrypted JSON index at `~/.agentid/index.json` holds
 * only public metadata.
 *
 * All methods are synchronous (Rust core blocks; typical latency is the
 * PBKDF2 derivation — ~60 ms on modern hardware).
 */
export const vault = {
  /** Default vault root: `~/.agentid`. */
  defaultRoot(): string {
    return getNative().vaultDefaultRoot();
  },

  /**
   * Initialise the vault directory tree. Safe to call repeatedly — if the
   * vault already exists, this is a no-op.
   */
  init(root?: string): void {
    getNative().vaultInit(root ?? this.defaultRoot());
  },

  /** List all stored identities (public metadata only). */
  list(root?: string): VaultEntry[] {
    return getNative()
      .vaultList(root ?? this.defaultRoot())
      .map(normaliseEntry);
  },

  /**
   * Derive a new identity from `(name, project, seed?)` and persist it
   * to the vault under `password`.
   */
  add(opts: {
    name: string;
    project: string;
    seed?: Uint8Array;
    password: string;
    root?: string;
  }): VaultEntry {
    const seedHex = opts.seed ? Buffer.from(opts.seed).toString("hex") : null;
    return normaliseEntry(
      getNative().vaultStore(
        opts.root ?? this.defaultRoot(),
        opts.name,
        opts.project,
        seedHex,
        opts.password,
      ),
    );
  },

  /**
   * Decrypt and load an identity by fingerprint. Returns a fully
   * functional {@link AgentIdentity} that can mint tokens.
   */
  load(opts: {
    fingerprint: string;
    password: string;
    root?: string;
  }): AgentIdentity {
    const rec = getNative().vaultLoadSecretHex(
      opts.root ?? this.defaultRoot(),
      opts.fingerprint,
      opts.password,
    );
    return AgentIdentity._fromNative(rec);
  },

  /** Remove an identity from the vault by fingerprint. */
  remove(opts: { fingerprint: string; root?: string }): void {
    getNative().vaultRemove(
      opts.root ?? this.defaultRoot(),
      opts.fingerprint,
    );
  },
};
