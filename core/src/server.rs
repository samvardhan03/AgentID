//! Optional gRPC server for centralised AgentID management.
//!
//! Wraps a [`Vault`] and exposes mint/verify/list RPCs. The server only
//! holds private keys decrypted in memory while servicing a request — the
//! vault password is supplied at startup (typically via
//! `AGENTID_VAULT_PASSWORD`) and held in a [`zeroize`]-on-drop wrapper.

use crate::token::{verify as verify_token, TokenBuilder};
use crate::vault::{Vault, VaultError};
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};
use zeroize::Zeroizing;

pub mod proto {
    tonic::include_proto!("agentid.v1");
}

use proto::agent_id_service_server::{AgentIdService, AgentIdServiceServer};
use proto::*;

pub struct AgentIdImpl {
    vault: Arc<Vault>,
    password: Arc<Zeroizing<String>>,
}

impl AgentIdImpl {
    pub fn new(vault: Vault, password: String) -> Self {
        Self {
            vault: Arc::new(vault),
            password: Arc::new(Zeroizing::new(password)),
        }
    }
}

#[tonic::async_trait]
impl AgentIdService for AgentIdImpl {
    async fn mint_token(
        &self,
        req: Request<MintTokenRequest>,
    ) -> Result<Response<MintTokenResponse>, Status> {
        let r = req.into_inner();
        let identity = self
            .vault
            .load(&r.fingerprint, self.password.as_str())
            .map_err(map_vault_err)?;
        let token = TokenBuilder::new(&identity)
            .scopes(r.scopes)
            .ttl_seconds(if r.ttl_seconds == 0 { 900 } else { r.ttl_seconds })
            .max_calls(r.max_calls)
            .build()
            .map_err(|e| Status::invalid_argument(format!("mint failed: {e}")))?;
        Ok(Response::new(MintTokenResponse {
            token,
            fingerprint: identity.fingerprint(),
        }))
    }

    async fn verify_token(
        &self,
        req: Request<VerifyTokenRequest>,
    ) -> Result<Response<VerifyTokenResponse>, Status> {
        let r = req.into_inner();
        let expected_pk = match r.expected_pubkey.len() {
            0 => None,
            32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&r.expected_pubkey);
                Some(a)
            }
            n => return Err(Status::invalid_argument(format!("expected_pubkey must be 32 bytes, got {n}"))),
        };
        match verify_token(&r.token, expected_pk.as_ref()) {
            Ok(claims) => Ok(Response::new(VerifyTokenResponse {
                valid: true,
                error: String::new(),
                name: claims.name.clone(),
                project: claims.project.clone(),
                scopes: claims.scopes.clone(),
                issued_at: claims.issued_at,
                expires_at: claims.expires_at,
                max_calls: claims.max_calls,
                issuer: claims.issuer.to_vec(),
                fingerprint: claims.fingerprint(),
            })),
            Err(e) => Ok(Response::new(VerifyTokenResponse {
                valid: false,
                error: format!("{e}"),
                ..Default::default()
            })),
        }
    }

    async fn list_identities(
        &self,
        _req: Request<ListIdentitiesRequest>,
    ) -> Result<Response<ListIdentitiesResponse>, Status> {
        let entries = self.vault.list().map_err(map_vault_err)?;
        let identities = entries
            .into_iter()
            .map(|e| Identity {
                name: e.name,
                project: e.project,
                fingerprint: e.fingerprint,
                public_key: e.public_key,
                created_at: e.created_at,
            })
            .collect();
        Ok(Response::new(ListIdentitiesResponse { identities }))
    }

    async fn health(
        &self,
        _req: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "ok".into(),
            version: crate::VERSION.into(),
        }))
    }
}

fn map_vault_err(e: VaultError) -> Status {
    match e {
        VaultError::NotFound(s) => Status::not_found(s),
        VaultError::DecryptionFailed => Status::permission_denied("vault password incorrect"),
        VaultError::NotInitialized(p) => {
            Status::failed_precondition(format!("vault not initialized at {}", p.display()))
        }
        e => Status::internal(format!("{e}")),
    }
}

/// Bind and serve the AgentID gRPC service on `addr` until the future is
/// dropped. The `password` is held in memory as long as the server is alive.
pub async fn serve(
    addr: SocketAddr,
    vault: Vault,
    password: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let svc = AgentIdImpl::new(vault, password);
    eprintln!(
        "agentid-server v{} listening on {addr}",
        crate::VERSION
    );
    Server::builder()
        .add_service(AgentIdServiceServer::new(svc))
        .serve(addr)
        .await?;
    Ok(())
}
