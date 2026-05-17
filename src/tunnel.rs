use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use russh::{client::Handle, keys::PrivateKeyWithHashAlg};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    time::sleep,
};
use tracing::{debug, error, info, warn};

use crate::{
    cli::SshArgs,
    client::ClientHandler,
    ssh_config::{self, HostConfig},
    ssh_forward::{ForwardKind, SshForward},
};

type SshHandle = Handle<ClientHandler>;
type SharedHandle = Arc<SshHandle>;

pub async fn run(args: SshArgs) -> Result<()> {
    let host_config = ssh_config::resolve(
        &args.ssh_host,
        args.port,
        args.user.as_deref(),
        args.identity.as_deref(),
    );

    let remote_forwards: Arc<Vec<SshForward>> = Arc::new(
        args.forwards
            .iter()
            .filter(|f| f.kind == ForwardKind::Remote)
            .cloned()
            .collect(),
    );

    let (handle_tx, handle_rx) = watch::channel::<Option<SharedHandle>>(None);

    for spec in args
        .forwards
        .iter()
        .filter(|f| f.kind == ForwardKind::Local)
    {
        let rx = handle_rx.clone();
        let spec = spec.clone();
        tokio::spawn(async move {
            if let Err(e) = local_forward_listener(spec, rx).await {
                error!("Local forward listener fatal error: {e:#}");
            }
        });
    }

    let mut delay = Duration::from_secs(1);
    let mut ever_connected = false;

    loop {
        let started_at = Instant::now();

        let result = connect_and_run(
            &host_config,
            &args,
            Arc::clone(&remote_forwards),
            &handle_tx,
        )
        .await;

        let was_connected = handle_tx.borrow().is_some();
        let _ = handle_tx.send(None);

        match result {
            Ok(()) => {
                info!("Shutdown complete");
                break;
            }
            Err(e) => {
                if !was_connected && !ever_connected {
                    return Err(e);
                }

                ever_connected = true;

                if started_at.elapsed() > Duration::from_secs(10) {
                    delay = Duration::from_secs(1);
                }

                warn!("Connection lost: {e:#}");
                warn!("Reconnecting in {delay:.0?}...");

                tokio::select! {
                    _ = sleep(delay) => {}
                    _ = tokio::signal::ctrl_c() => {
                        info!("Interrupted during reconnect wait, exiting");
                        return Ok(());
                    }
                }

                delay = (delay * 2).min(Duration::from_secs(60));
            }
        }
    }

    Ok(())
}

async fn connect_and_run(
    host_config: &HostConfig,
    args: &SshArgs,
    remote_forwards: Arc<Vec<SshForward>>,
    handle_tx: &watch::Sender<Option<SharedHandle>>,
) -> Result<()> {
    let ssh_config = Arc::new(russh::client::Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        ..Default::default()
    });

    let addr = (host_config.hostname.as_str(), host_config.port);
    info!(
        "Connecting to {}:{} as {}",
        host_config.hostname, host_config.port, host_config.user
    );

    let handler = ClientHandler::new(Arc::clone(&remote_forwards));
    let mut handle = russh::client::connect(ssh_config, addr, handler)
        .await
        .context("SSH TCP connect failed")?;

    authenticate(&mut handle, host_config, &args.password).await?;
    info!("Authenticated as {}", host_config.user);

    for spec in remote_forwards.iter() {
        let bound_port = handle
            .tcpip_forward(&spec.bind_host, spec.bind_port as u32)
            .await
            .with_context(|| {
                format!(
                    "Failed to request remote forward {} (listen on SSH server)",
                    SshForward::socket_addr(&spec.bind_host, spec.bind_port)
                )
            })?;
        info!(
            "Remote forward: {} → {} (server listening on port {})",
            SshForward::socket_addr(&spec.bind_host, spec.bind_port),
            SshForward::socket_addr(&spec.dest_host, spec.dest_port),
            bound_port
        );
    }

    let arc_handle = Arc::new(handle);
    let _ = handle_tx.send(Some(Arc::clone(&arc_handle)));

    let ping_handle = Arc::clone(&arc_handle);
    let (dead_tx, dead_rx) = tokio::sync::oneshot::channel::<anyhow::Error>();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;

        loop {
            interval.tick().await;
            if let Err(e) = ping_handle.send_ping().await {
                let _ =
                    dead_tx.send(anyhow::anyhow!("Keepalive ping failed: {e}"));
                break;
            }
        }
    });

    tokio::select! {
        result = dead_rx => {
            match result {
                Ok(e) => Err(e),
                Err(_) => Ok(()),
            }
        }
        result = tokio::signal::ctrl_c() => {
            result.context("Failed to listen for Ctrl+C")?;
            info!("Ctrl+C received, disconnecting...");
            let _ = arc_handle
                .disconnect(russh::Disconnect::ByApplication, "user request", "en")
                .await;
            Ok(())
        }
    }
}

async fn authenticate(
    handle: &mut SshHandle,
    host_config: &HostConfig,
    password: &Option<String>,
) -> Result<()> {
    let user = &host_config.user;

    for key_path in &host_config.identity_files {
        if !key_path.exists() {
            continue;
        }
        debug!("Trying key: {}", key_path.display());

        match russh::keys::load_secret_key(key_path, None) {
            Ok(key) => {
                let hash_alg = if key.algorithm().is_rsa() {
                    match handle.best_supported_rsa_hash().await {
                        Ok(Some(alg)) => alg,
                        Ok(None) => {
                            debug!("Server does not support RSA, skipping key");
                            continue;
                        }
                        Err(e) => {
                            debug!("Could not query RSA hash algorithm: {e}");
                            None
                        }
                    }
                } else {
                    None
                };
                let key_with_alg =
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
                match handle.authenticate_publickey(user, key_with_alg).await {
                    Ok(result) if result.success() => {
                        debug!(
                            "Authenticated with key: {}",
                            key_path.display()
                        );
                        return Ok(());
                    }
                    Ok(_) => {
                        debug!("Key rejected: {}", key_path.display());
                    }
                    Err(e) => {
                        debug!(
                            "Key auth error for {}: {e}",
                            key_path.display()
                        );
                    }
                }
            }
            Err(e) => {
                debug!("Cannot load key {}: {e}", key_path.display());
            }
        }
    }

    if let Some(pwd) = password {
        match handle.authenticate_password(user, pwd).await {
            Ok(result) if result.success() => {
                debug!("Authenticated with password");
                return Ok(());
            }
            Ok(_) => {
                anyhow::bail!("Password authentication rejected by server");
            }
            Err(e) => {
                return Err(e).context("Password authentication failed");
            }
        }
    }

    anyhow::bail!(
        "All authentication methods failed for user '{}'. \
         Tried {} key(s){}.",
        user,
        host_config.identity_files.len(),
        if password.is_some() {
            " and password"
        } else {
            ""
        }
    )
}

async fn local_forward_listener(
    spec: SshForward,
    handle_rx: watch::Receiver<Option<SharedHandle>>,
) -> Result<()> {
    let bind_addr = SshForward::socket_addr(&spec.bind_host, spec.bind_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind local address {bind_addr}"))?;

    info!(
        "Local forward (-L): {} → {}",
        bind_addr,
        SshForward::socket_addr(&spec.dest_host, spec.dest_port)
    );

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("accept() error on {bind_addr}: {e}");
                continue;
            }
        };
        debug!("Accepted {peer_addr} → {bind_addr}");

        let dest_host = spec.dest_host.clone();
        let dest_port = spec.dest_port;
        let mut rx = handle_rx.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_local_connection(stream, dest_host, dest_port, &mut rx)
                    .await
            {
                debug!("Local forward connection closed: {e}");
            }
        });
    }
}

async fn handle_local_connection(
    mut stream: TcpStream,
    dest_host: String,
    dest_port: u16,
    handle_rx: &mut watch::Receiver<Option<SharedHandle>>,
) -> Result<()> {
    let handle = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            {
                let guard = handle_rx.borrow_and_update();
                if let Some(h) = guard.as_ref() {
                    return Ok::<SharedHandle, anyhow::Error>(Arc::clone(h));
                }
            }
            handle_rx.changed().await.context("Handle watcher closed")?;
        }
    })
    .await
    .context("Timeout waiting for SSH tunnel to become ready")??;

    let channel = handle
        .channel_open_direct_tcpip(&dest_host, dest_port as u32, "127.0.0.1", 0)
        .await
        .context("Failed to open direct-tcpip channel")?;

    let mut ch_stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut stream, &mut ch_stream)
        .await
        .context("Data transfer error")?;

    Ok(())
}
