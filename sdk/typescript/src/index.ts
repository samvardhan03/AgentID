export { AgentIdentity } from "./identity.js";
export { verifyToken, tryVerifyToken, parseToken } from "./verify.js";
export { vault } from "./vault.js";
export type {
  IdentityRecord,
  TokenClaims,
  VerifyResult,
  VaultEntry,
  MintOptions,
} from "./types.js";

import { getNative } from "./native.js";

/** Library version (from the compiled Rust core). */
export function version(): string {
  return getNative().version();
}
