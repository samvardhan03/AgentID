#!/usr/bin/env bun

import { cac } from "cac";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Writable } from "node:stream";

import {
  vault,
  verifyToken,
  parseToken,
  version,
} from "../sdk/typescript/src/index.js";

import type { TokenClaims } from "../sdk/typescript/src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");

const cli = cac("agentid");

// cac doesn't await async action handlers. We store the pending promise
// and top-level-await it after cli.parse().
let pendingAction: Promise<void> | undefined;

// ──────────────────────────── init ────────────────────────────

cli
  .command("init", "Initialise the local AgentID vault (~/.agentid)")
  .option("--root <path>", "Vault root directory")
  .action((opts: { root?: string }) => {
    const root = opts.root ?? vault.defaultRoot();
    vault.init(root);
    console.log(`Vault initialised at ${root}`);
  });

// ──────────────────────── keys <action> ───────────────────────

cli
  .command("keys [action] [...args]", "Manage vault identities (list | add | remove <fp>)")
  .option("--name <name>", "Agent name (for 'add')")
  .option("--project <project>", "Project name (for 'add')")
  .option("--seed <hex>", "Optional seed hex (for 'add')")
  .option("--root <path>", "Vault root directory")
  .option("--json", "Output as JSON (for 'list')")
  .action((action: string | undefined, rest: string[], opts: {
    name?: string; project?: string; seed?: string;
    root?: string; json?: boolean;
  }) => {
    const cmd = action ?? "list";

    if (cmd === "list") {
      const entries = vault.list(opts.root);
      if (opts.json) {
        console.log(JSON.stringify(entries, null, 2));
        return;
      }
      if (entries.length === 0) {
        console.log("(no identities stored — run `agentid keys add` first)");
        return;
      }
      const nameW = 20;
      const projW = 20;
      console.log(
        "NAME".padEnd(nameW) +
          "PROJECT".padEnd(projW) +
          "FINGERPRINT",
      );
      console.log("-".repeat(nameW + projW + 30));
      for (const e of entries) {
        console.log(
          e.name.padEnd(nameW) +
            e.project.padEnd(projW) +
            e.fingerprint,
        );
      }
    } else if (cmd === "add") {
      pendingAction = (async () => {
        if (!opts.name || !opts.project) {
          console.error("Error: --name and --project are required.");
          process.exit(2);
        }
        const password = await getPassword("Vault password: ", true);
        const seed = opts.seed ? hexToBytes(opts.seed) : undefined;
        const entry = vault.add({
          name: opts.name,
          project: opts.project,
          seed,
          password,
          root: opts.root,
        });
        console.log();
        console.log(`Identity stored.`);
        console.log(`  fingerprint  ${entry.fingerprint}`);
        console.log(`  name         ${entry.name}`);
        console.log(`  project      ${entry.project}`);
        console.log(`  public_key   ${entry.publicKey}`);
      })();
    } else if (cmd === "remove") {
      const fp = rest[0];
      if (!fp) {
        console.error("Usage: agentid keys remove <fingerprint>");
        process.exit(2);
      }
      vault.remove({ fingerprint: fp, root: opts.root });
      console.log(`Removed ${fp}`);
    } else {
      console.error(`Unknown keys action: "${cmd}". Use list, add, or remove.`);
      process.exit(2);
    }
  });

// ──────────────────────────── mint ────────────────────────────

cli
  .command("mint", "Mint a scoped token from a stored identity")
  .option("--name <name>", "Agent name")
  .option("--project <project>", "Project name")
  .option("--fingerprint <fp>", "Identity fingerprint (alternative to name/project)")
  .option("--scopes <scopes>", "Comma-separated scope list")
  .option("--ttl <seconds>", "Token TTL in seconds (default: 900)", { default: "900" })
  .option("--max-calls <n>", "Per-token call quota (0 = unlimited)")
  .option("--format <fmt>", "Output: base64 | hex | raw (default: base64)", { default: "base64" })
  .option("--root <path>", "Vault root directory")
  .action((opts: {
    name?: string; project?: string; fingerprint?: string;
    scopes?: string; ttl?: string; maxCalls?: string;
    format?: string; root?: string;
  }) => {
    pendingAction = (async () => {
      const root = opts.root ?? vault.defaultRoot();
      let fingerprint = opts.fingerprint;

      if (!fingerprint) {
        if (!opts.name || !opts.project) {
          console.error("Error: provide --fingerprint, or both --name and --project.");
          process.exit(2);
        }
        const entries = vault.list(root);
        const match = entries.find(
          (e) => e.name === opts.name && e.project === opts.project,
        );
        if (!match) {
          console.error(`Error: no identity "${opts.name}@${opts.project}" in vault.`);
          console.error("Run `agentid keys list` to see stored identities.");
          process.exit(1);
        }
        fingerprint = match.fingerprint;
      }

      const password = await getPassword("Vault password: ");
      const identity = vault.load({ fingerprint, password, root });

      const scopes = opts.scopes
        ? opts.scopes.split(",").map((s) => s.trim()).filter(Boolean)
        : [];

      const token = identity.mintToken({
        scopes,
        ttlSeconds: Number(opts.ttl),
        maxCalls: opts.maxCalls ? Number(opts.maxCalls) : 0,
      });

      const fmt = opts.format ?? "base64";
      if (fmt === "raw") {
        process.stdout.write(token);
      } else if (fmt === "hex") {
        console.log(Buffer.from(token).toString("hex"));
      } else {
        console.log(Buffer.from(token).toString("base64"));
      }
    })();
  });

// ──────────────────────────── verify ──────────────────────────

cli
  .command("verify <token>", "Verify a token and print its claims")
  .option("--format <fmt>", "Input format: base64 | hex (default: base64)", { default: "base64" })
  .option("--pubkey <hex>", "Expected issuer public key (hex)")
  .option("--json", "Output as JSON")
  .action((token: string, opts: { format?: string; pubkey?: string; json?: boolean }) => {
    const buf =
      opts.format === "hex"
        ? Buffer.from(token, "hex")
        : Buffer.from(token, "base64");

    try {
      const claims = verifyToken(new Uint8Array(buf), opts.pubkey);
      if (opts.json) {
        console.log(JSON.stringify(claims, null, 2));
      } else {
        printClaims(claims);
      }
    } catch (err) {
      console.error(`Verification failed: ${(err as Error).message}`);
      process.exit(1);
    }
  });

// ──────────────────────────── inspect ─────────────────────────

cli
  .command("inspect <token>", "Parse a token without verifying (debug only)")
  .option("--format <fmt>", "Input format: base64 | hex (default: base64)", { default: "base64" })
  .option("--json", "Output as JSON")
  .action((token: string, opts: { format?: string; json?: boolean }) => {
    const buf =
      opts.format === "hex"
        ? Buffer.from(token, "hex")
        : Buffer.from(token, "base64");

    try {
      const claims = parseToken(new Uint8Array(buf));
      if (opts.json) {
        console.log(JSON.stringify(claims, null, 2));
      } else {
        console.log("(unverified — signature NOT checked)");
        printClaims(claims);
      }
    } catch (err) {
      console.error(`Parse failed: ${(err as Error).message}`);
      process.exit(1);
    }
  });

// ──────────────────────────── serve ───────────────────────────

cli
  .command("serve", "Start the AgentID gRPC server")
  .option("--port <port>", "Bind port (default: 6100)", { default: "6100" })
  .option("--bind <ip>", "Bind address (default: 127.0.0.1)", { default: "127.0.0.1" })
  .action((opts: { port?: string; bind?: string }) => {
    pendingAction = (async () => {
      const password = await getPassword("Vault password (for server): ");
      const bin = locateServerBinary();

      if (!bin) {
        const candidates = serverBinaryCandidates();
        console.error(
          [
            "Error: could not find the agentid-server binary.",
            "",
            "Searched:",
            ...candidates.map((p) => `  ${p}`),
            "",
            "Build it:",
            "  cd core && cargo build --release",
            "",
            "Or set AGENTID_SERVER_BIN to its path.",
          ].join("\n"),
        );
        process.exit(2);
      }

      console.log(`Starting agentid-server on ${opts.bind}:${opts.port} ...`);

      const child = spawn(bin, ["--port", String(opts.port), "--bind", String(opts.bind)], {
        stdio: "inherit",
        env: { ...process.env, AGENTID_VAULT_PASSWORD: password },
      });

      const forwardSignal = (sig: NodeJS.Signals) => {
        process.on(sig, () => {
          try { child.kill(sig); } catch { /* already exited */ }
        });
      };
      forwardSignal("SIGINT");
      forwardSignal("SIGTERM");

      child.on("error", (err) => {
        console.error(`agentid-server: ${err.message}`);
        process.exit(1);
      });

      child.on("exit", (code, signal) => {
        if (signal) {
          process.kill(process.pid, signal);
        } else {
          process.exit(code ?? 0);
        }
      });
    })();
  });

// ──────────────────────────── version ─────────────────────────

cli.command("version", "Print the AgentID version").action(() => {
  try {
    console.log(`agentid ${version()} (core)`);
  } catch {
    console.log("agentid 0.1.0 (core not loaded)");
  }
});

// ──────────────────────────── parse + run ─────────────────────

cli.help();
cli.version("0.1.0");

try {
  cli.parse();
} catch (err) {
  if (err instanceof Error && err.message.includes("Unknown")) {
    console.error(err.message);
    console.error("Run `agentid --help` for available commands.");
    process.exit(2);
  }
  throw err;
}

if (pendingAction) {
  try {
    await pendingAction;
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
}

// ──────────────────────────── helpers ─────────────────────────

async function getPassword(prompt: string, confirm = false): Promise<string> {
  const env = process.env["AGENTID_VAULT_PASSWORD"];
  if (env) return env;

  const pw = await readHidden(prompt);
  if (!pw) {
    console.error("Error: password must not be empty.");
    process.exit(2);
  }

  if (confirm) {
    const pw2 = await readHidden("Confirm password: ");
    if (pw !== pw2) {
      console.error("Error: passwords do not match.");
      process.exit(2);
    }
  }

  return pw;
}

function readHidden(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const muted = new Writable({ write(_c, _e, cb) { cb(); } });
    const rl = createInterface({ input: process.stdin, output: muted, terminal: true });
    rl.question("", (answer: string) => {
      rl.close();
      process.stdout.write("\n");
      resolve(answer);
    });
  });
}

function serverBinaryCandidates(): string[] {
  const paths: string[] = [];
  const envBin = process.env["AGENTID_SERVER_BIN"];
  if (envBin) paths.push(envBin);
  for (const profile of ["release", "debug"]) {
    paths.push(join(repoRoot, "core", "target", profile, "agentid-server"));
  }
  return paths;
}

function locateServerBinary(): string | null {
  for (const p of serverBinaryCandidates()) {
    if (existsSync(p)) return p;
  }
  return null;
}

function printClaims(c: TokenClaims): void {
  console.log("Token verified.");
  console.log(`  name         ${c.name}`);
  console.log(`  project      ${c.project}`);
  console.log(`  fingerprint  ${c.fingerprint}`);
  console.log(`  scopes       ${c.scopes.length > 0 ? c.scopes.join(", ") : "(none)"}`);
  console.log(`  issued       ${new Date(c.issuedAt * 1000).toISOString()}`);
  console.log(`  expires      ${new Date(c.expiresAt * 1000).toISOString()}`);
  console.log(`  max_calls    ${c.maxCalls || "unlimited"}`);
  console.log(`  token_id     ${c.tokenId}`);
  console.log(`  issuer       ${c.issuer}`);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
