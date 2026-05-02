#!/usr/bin/env node

/**
 * build-native.mjs
 *
 * 1. Runs `cargo build [--release] --features napi-bindings` in core/.
 * 2. Renames the resulting cdylib to `native/agentid-core.<platform>-<arch>.node`.
 *
 * Flags:
 *   --debug   Use the dev profile (default: release).
 *
 * Env:
 *   PROTOC    Path to the protobuf compiler (if not on $PATH).
 */

import { spawn } from "node:child_process";
import { copyFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const sdkRoot = resolve(__dirname, "..");
const repoRoot = resolve(sdkRoot, "..", "..");
const coreDir = join(repoRoot, "core");

const isRelease = !process.argv.includes("--debug");
const profile = isRelease ? "release" : "debug";

/** Platform-specific cdylib naming conventions. */
const platformMap = /** @type {const} */ ({
  darwin: { prefix: "lib", ext: "dylib" },
  linux: { prefix: "lib", ext: "so" },
  win32: { prefix: "", ext: "dll" },
});

const plat = platformMap[/** @type {keyof typeof platformMap} */ (process.platform)];
if (!plat) {
  console.error(`[build-native] unsupported platform: ${process.platform}`);
  process.exit(1);
}

const triple = `${process.platform}-${process.arch}`;
const sourceFile = `${plat.prefix}agentid_core.${plat.ext}`;
const sourcePath = join(coreDir, "target", profile, sourceFile);

const destDir = join(sdkRoot, "native");
const destName = `agentid-core.${triple}.node`;
const destPath = join(destDir, destName);

console.log(`[build-native] platform : ${triple}`);
console.log(`[build-native] profile  : ${profile}`);
console.log(`[build-native] source   : ${sourcePath}`);
console.log(`[build-native] dest     : ${destPath}`);
console.log();

// ---- step 1: cargo build ----

await new Promise((ok, fail) => {
  const args = [
    "build",
    "--lib",
    "--manifest-path", join(coreDir, "Cargo.toml"),
    "--features", "napi-bindings",
  ];
  if (isRelease) args.push("--release");

  const env = { ...process.env };
  // Forward PROTOC if set, else let cargo/tonic-build find it.
  if (!env.PROTOC) delete env.PROTOC;

  console.log(`$ cargo ${args.join(" ")}\n`);

  const child = spawn("cargo", args, { stdio: "inherit", env });
  child.on("error", fail);
  child.on("exit", (code) =>
    code === 0 ? ok(undefined) : fail(new Error(`cargo build exited with code ${code}`)),
  );
});

// ---- step 2: copy + rename ----

if (!existsSync(sourcePath)) {
  console.error(`\n[build-native] ERROR: expected artifact not found at:`);
  console.error(`  ${sourcePath}`);
  console.error(`\nCargo build succeeded but the cdylib was not produced.`);
  console.error(`Make sure Cargo.toml has: crate-type = ["cdylib", "rlib"]`);
  process.exit(1);
}

await mkdir(destDir, { recursive: true });
await copyFile(sourcePath, destPath);

console.log(`\n[build-native] wrote ${destPath}`);
console.log(`[build-native] done.`);
