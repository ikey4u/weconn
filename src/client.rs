use russh::{
    Channel,
    client::{Handler, Msg, Session},
};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::cli::ForwardSpec;

pub struct ClientHandler {
    remote_specs: Vec<ForwardSpec>,
}

impl ClientHandler {
    pub fn new(remote_specs: Vec<ForwardSpec>) -> Self {
        Self { remote_specs }
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
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let port = connected_port as u16;
        let addr = connected_address.to_string();

        let spec = match self.remote_specs.iter().find(|s| s.bind_port == port)
        {
            Some(s) => s.clone(),
            None => {
                warn!(
                    "No remote forward spec for forwarded-tcpip on {addr}:{port}"
                );
                return Ok(());
            }
        };

        let dest = format!("{}:{}", spec.dest_host, spec.dest_port);

        tokio::spawn(async move {
            match TcpStream::connect(&dest).await {
                Ok(mut tcp) => {
                    let mut ch = channel.into_stream();
                    match tokio::io::copy_bidirectional(&mut tcp, &mut ch).await
                    {
                        Ok((a, b)) => {
                            debug!("Remote forward {dest}: {a}↑ {b}↓ bytes")
                        }
                        Err(e) => debug!("Remote forward {dest} ended: {e}"),
                    }
                }
                Err(e) => {
                    warn!("Remote forward: cannot connect to {dest}: {e}")
                }
            }
        });

        Ok(())
    }
}
