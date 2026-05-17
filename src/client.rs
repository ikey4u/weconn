use std::sync::Arc;

use anyhow::Context;
use russh::client::{Handler, Session};
use tokio::net::TcpStream;
use tracing::debug;

use crate::ssh_forward::{ForwardKind, SshForward};

pub struct ClientHandler {
    remote_forwards: Arc<Vec<SshForward>>,
}

impl ClientHandler {
    pub fn new(remote_forwards: Arc<Vec<SshForward>>) -> Self {
        Self { remote_forwards }
    }
}

impl Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let spec = self
            .remote_forwards
            .iter()
            .find(|f| {
                f.kind == ForwardKind::Remote
                    && f.bind_port as u32 == connected_port
            })
            .or_else(|| {
                self.remote_forwards.iter().find(|f| {
                    f.kind == ForwardKind::Remote
                        && f.bind_host == connected_address
                        && f.bind_port as u32 == connected_port
                })
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no remote forward registered for {connected_address}:{connected_port}"
                )
            })?;

        let dest = SshForward::socket_addr(&spec.dest_host, spec.dest_port);
        debug!(
            "Remote forward accepted {originator_address}:{originator_port} \
             on {connected_address}:{connected_port} → {dest}"
        );

        let mut local = TcpStream::connect(&dest).await.with_context(|| {
            format!("Failed to connect local target {dest}")
        })?;
        let mut remote = channel.into_stream();
        tokio::io::copy_bidirectional(&mut local, &mut remote)
            .await
            .context("Remote forward data transfer error")?;

        Ok(())
    }
}
