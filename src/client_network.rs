use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status, transport::{Server, Channel}};

use crate::client_helper::{generate_keys, generate_vrf_output};
use transfer_sign::transfer_sign_server::{TransferSign, TransferSignServer};
use transfer_sign::{GetPartSignRequest, Ack as SignAck};
use mesh::mesh_client::MeshClient;
use mesh::{NodeAccount, CommitteeCandidateInfo, Ack as MeshAck};

pub mod transfer_sign {
    tonic::include_proto!("transfer_sign");
}

pub mod mesh {
    tonic::include_proto!("mesh");
}

static ROUND: RwLock<u64> = RwLock::const_new(0);

/// Per-round state for signature aggregation
struct RoundState {
    node_id: String,
    committee_size: usize,
    public_keys: Vec<ed25519_dalek::PublicKey>,
    agg_commit: Vec<u8>,
    sig_parts: Vec<Vec<u8>>,
    count: usize,
}

#[derive(Clone)]
pub struct TransferServer {
    inner: Arc<Mutex<std::collections::HashMap<u64, RoundState>>>,
}

impl TransferServer {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(Default::default())) }
    }
}

#[tonic::async_trait]
impl TransferSign for TransferServer {
    async fn get_part_sign(
        &self,
        request: Request<GetPartSignRequest>,
    ) -> Result<Response<SignAck>, Status> {
        let req = request.into_inner();
        let mut map = self.inner.lock().unwrap();
        if let Some(state) = map.get_mut(&req.round) {
            state.sig_parts.push(req.part_sign);
            state.count += 1;
            if state.count == state.committee_size {
                // TODO: aggregation and verification
                state.count = 0;
                state.sig_parts.clear();
            }
        }
        Ok(Response::new(SignAck { ok: true }))
    }
}

/// Start gRPC server for TransferSign
pub async fn start_client_server(ts: Arc<TransferServer>) -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:50052".parse()?;
    Server::builder()
        .add_service(TransferSignServer::new((*ts).clone()))
        .serve(addr)
        .await?;
    Ok(())
}

/// Run Mesh client logic
pub async fn run_client(
    node_id: String,
    ts: Arc<TransferServer>,
) -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_static("http://interface-server1:50051").connect().await?;
    let mut client = MeshClient::new(channel);
    // TODO: subscribe, VRF, RequestCommittee flows
    Ok(())
}