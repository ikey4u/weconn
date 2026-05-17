use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    time::sleep,
};
use tracing::{debug, error, info, warn};

use crate::{
    cli::SshArgs,
    ssh_config::{self, ResolvedTarget},
    ssh_forward::{ForwardKind, SshForward},
    ssh_session::{self, SessionHolder},
};

type SharedSession = Arc<SessionHolder>;

pub async fn run(args: SshArgs) -> Result<()> {
    let target = ssh_config::resolve_target(
        &args.ssh_host,
        args.port,
        args.user.as_deref(),
        args.identity.as_deref(),
        &args.proxy_jump,
    )?;

    if target.jumps.is_empty() {
        info!(
            "SSH target: {}:{}",
            target.destination.hostname, target.destination.port
        );
    } else {
        info!("SSH path: {}", target.path_label());
    }

    let remote_forwards: Arc<Vec<SshForward>> = Arc::new(
        args.forwards
            .iter()
            .filter(|f| f.kind == ForwardKind::Remote)
            .cloned()
            .collect(),
    );

    let (session_tx, session_rx) =
        watch::channel::<Option<SharedSession>>(None);

    for spec in args
        .forwards
        .iter()
        .filter(|f| f.kind == ForwardKind::Local)
    {
        let rx = session_rx.clone();
        let spec = spec.clone();
        tokio::spawn(async move {
            if let Err(e) = local_forward_listener(spec, rx).await {
                error!("Local forward listener fatal error: {e:#}");
            }
        });
    }

    let mut delay = Duration::from_secs(1);
    let mut ever_connected = false;
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;
        let started_at = Instant::now();

        if attempt > 1 {
            info!("Reconnect attempt {attempt} via {}", target.path_label());
        }

        let result = connect_and_run(
            &target,
            &args.password,
            Arc::clone(&remote_forwards),
            &session_tx,
        )
        .await;

        let was_connected = session_tx.borrow().is_some();
        let _ = session_tx.send(None);

        match result {
            Ok(()) => {
                info!("Shutdown complete");
                break;
            }
            Err(e) => {
                if !was_connected && !ever_connected {
                    return Err(e).context(format!(
                        "Initial connection failed (path: {})",
                        target.path_label()
                    ));
                }

                ever_connected = true;

                if started_at.elapsed() > Duration::from_secs(10) {
                    delay = Duration::from_secs(1);
                }

                warn!("Tunnel down: {e:#}");
                warn!(
                    "Reconnecting in {delay:.0?} (local -L listeners stay up)..."
                );

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
    target: &ResolvedTarget,
    password: &Option<String>,
    remote_forwards: Arc<Vec<SshForward>>,
    session_tx: &watch::Sender<Option<SharedSession>>,
) -> Result<()> {
    let session = ssh_session::connect_target(
        target,
        password,
        Arc::clone(&remote_forwards),
    )
    .await
    .with_context(|| {
        format!("SSH session setup failed for {}", target.path_label())
    })?;

    for spec in remote_forwards.iter() {
        let bound_port = session
            .handle
            .tcpip_forward(&spec.bind_host, spec.bind_port as u32)
            .await
            .with_context(|| {
                format!(
                    "Failed to request remote forward {} on {}",
                    SshForward::socket_addr(&spec.bind_host, spec.bind_port),
                    target.destination.hostname
                )
            })?;
        info!(
            "Remote forward (-R): {} → {} (listening on port {})",
            SshForward::socket_addr(&spec.bind_host, spec.bind_port),
            SshForward::socket_addr(&spec.dest_host, spec.dest_port),
            bound_port
        );
    }

    let shared = session.into_shared();
    let _ = session_tx.send(Some(Arc::clone(&shared)));

    info!(
        "Tunnel ready ({} hop(s)); forwards active",
        target.hop_count()
    );

    let ping_session = Arc::clone(&shared);
    let (dead_tx, dead_rx) = tokio::sync::oneshot::channel::<anyhow::Error>();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;

        loop {
            interval.tick().await;
            if let Err(e) = ping_session.handle.send_ping().await {
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
            let _ = shared
                .handle
                .disconnect(russh::Disconnect::ByApplication, "user request", "en")
                .await;
            Ok(())
        }
    }
}

async fn local_forward_listener(
    spec: SshForward,
    session_rx: watch::Receiver<Option<SharedSession>>,
) -> Result<()> {
    let bind_addr = SshForward::socket_addr(&spec.bind_host, spec.bind_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind local address {bind_addr}"))?;

    info!(
        "Local forward (-L): {} → {} (listener stays up across reconnects)",
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
        let mut rx = session_rx.clone();

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
    session_rx: &mut watch::Receiver<Option<SharedSession>>,
) -> Result<()> {
    let session = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            {
                let guard = session_rx.borrow_and_update();
                if let Some(s) = guard.as_ref() {
                    return Ok::<SharedSession, anyhow::Error>(Arc::clone(s));
                }
            }
            session_rx
                .changed()
                .await
                .context("Session watcher closed")?;
        }
    })
    .await
    .context("Timeout waiting for SSH tunnel (still reconnecting?)")??;

    let channel = session
        .handle
        .channel_open_direct_tcpip(&dest_host, dest_port as u32, "127.0.0.1", 0)
        .await
        .context("Failed to open direct-tcpip channel")?;

    let mut ch_stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut stream, &mut ch_stream)
        .await
        .context("Data transfer error")?;

    Ok(())
}
