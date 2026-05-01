//! `agentid-server` — the gRPC server binary.
//!
//! Configuration is read from the environment to keep secrets out of the
//! command line:
//!
//! * `AGENTID_VAULT_PASSWORD` (required) — vault decryption password.
//! * `AGENTID_HOME`           (optional) — vault root, defaults to `~/.agentid`.
//!
//! Flags:
//! * `--port <u16>` (default 6100)
//! * `--bind <ip>`  (default 127.0.0.1; pass 0.0.0.0 to expose externally)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = arg_value(&args, "--port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(6100);
    let bind = arg_value(&args, "--bind").unwrap_or_else(|| "127.0.0.1".to_string());

    let addr: SocketAddr = match format!("{bind}:{port}").parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("agentid-server: invalid bind address: {e}");
            return ExitCode::from(2);
        }
    };

    let password = match std::env::var("AGENTID_VAULT_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            eprintln!("agentid-server: AGENTID_VAULT_PASSWORD must be set");
            return ExitCode::from(2);
        }
    };

    let root: PathBuf = std::env::var_os("AGENTID_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".agentid")))
        .unwrap_or_else(|| PathBuf::from(".agentid"));

    let vault = agentid_core::vault::Vault::new(root);
    if !vault.is_initialized() {
        eprintln!(
            "agentid-server: vault is not initialised at {}. Run `agentid init` first.",
            vault.root().display()
        );
        return ExitCode::from(2);
    }

    if let Err(e) = agentid_core::server::serve(addr, vault, password).await {
        eprintln!("agentid-server: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().enumerate().find_map(|(i, a)| {
        if a == flag {
            args.get(i + 1).cloned()
        } else if let Some(eq) = a.strip_prefix(&format!("{flag}=")) {
            Some(eq.to_string())
        } else {
            None
        }
    })
}
