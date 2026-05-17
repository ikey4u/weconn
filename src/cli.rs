use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use url::Url;

use crate::ssh_forward::{ForwardKind, SshForward};

#[derive(Parser)]
#[command(
    name = "weconn",
    about = "Stable connection tools",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
enum CliCommand {
    #[command(
        about = "Bridge TCP streams directly or over WebSocket",
        long_about = concat!(
            "weconn bridge forwards TCP streams directly, TCP streams to WebSocket streams, or WebSocket streams to TCP.\n",
            "\n",
            "  --to    where clients connect (local listener)\n",
            "  --from  upstream weconn dials for each accepted connection\n",
            "\n",
            "SUPPORTED ENDPOINTS:\n",
            "  --to    tcp://host:port, ws://host:port/path, or http://host:port/path\n",
            "  --from  tcp://host:port, ws://host:port/path, wss://host:port/path, http://host:port/path, or https://host:port/path\n",
            "  --token optional bearer token for WebSocket authorization\n",
            "\n",
            "NOTES:\n",
            "  tcp:// on both sides = direct TCP relay\n",
            "  http:// endpoints are treated as ws:// via HTTP Upgrade; https:// --from => wss://\n",
            "  wss:// and https:// --to are not supported yet (no TLS server)\n",
            "  --token on --to: checked via Authorization header or ?token= query\n",
            "  --token on --from: sent as Authorization: Bearer <token>\n",
            "\n",
            "EXAMPLES:\n",
            "  weconn bridge --to tcp://0.0.0.0:8080 --from tcp://127.0.0.1:80\n",
            "  weconn bridge --to tcp://127.0.0.1:3306 --from wss://public.com:443/wss\n",
            "  weconn bridge --to http://0.0.0.0:8080/ws --from tcp://mysql:3306\n",
            "  weconn bridge --to http://0.0.0.0:8080/ws --from tcp://mysql:3306 --token secret"
        )
    )]
    Bridge(BridgeCli),

    #[command(
        about = "Stable SSH port forwarding with auto-reconnect",
        long_about = concat!(
            "OpenSSH-compatible -L / -R with automatic reconnect.\n",
            "\n",
            "SYNTAX\n",
            "  [bind_host:]bind_port:remote_host:remote_port\n",
            "\n",
            "  bind_host omitted     listens on 127.0.0.1 only\n",
            "  bind_host 0.0.0.0     listens on all interfaces\n",
            "  bind_host <IP>        listens on that address only\n",
            "\n",
            "  -L  WHO LISTENS: your PC (bind_port)\n",
            "      WHO CONNECTS TO TARGET: the SSH server → remote_host:remote_port\n",
            "      (target must be reachable FROM the server, not necessarily from your PC)\n",
            "\n",
            "  -R  WHO LISTENS: the SSH server (bind_port)\n",
            "      WHO CONNECTS TO TARGET: your PC → remote_host:remote_port\n",
            "      (target must be reachable FROM your PC, e.g. 127.0.0.1 or your LAN)\n",
            "\n",
            "EXAMPLES\n",
            "\n",
            "  Local (-L), localhost only:\n",
            "    weconn ssh -L 3307:10.0.0.5:3306 myserver\n",
            "\n",
            "  Local (-L), LAN clients allowed:\n",
            "    weconn ssh -L 0.0.0.0:8080:10.0.0.5:80 myserver\n",
            "\n",
            "  Local (-L), one interface:\n",
            "    weconn ssh -L 192.168.1.50:3307:10.0.0.5:3306 myserver\n",
            "\n",
            "  Remote (-R), server localhost only:\n",
            "    weconn ssh -R 127.0.0.1:9000:127.0.0.1:3000 myserver\n",
            "\n",
            "  Remote (-R), server all interfaces → your LAN host:\n",
            "    weconn ssh -R 0.0.0.0:9000:192.168.1.20:3000 myserver\n",
            "\n",
            "  Multiple -L / -R:\n",
            "    weconn ssh -L 3307:10.0.0.5:3306 -L 6380:10.0.0.5:6379 myserver\n",
            "\n",
            "  ProxyJump (-J or ProxyJump in ~/.ssh/config):\n",
            "    weconn ssh -J bastion -L 3307:mysql.internal:3306 app-server\n",
            "    weconn ssh -J hop1,hop2 -L 3307:10.0.0.5:3306 target\n",
            "\n",
            "NOTES\n",
            "  Repeat -L, -R, or -J to add more. IPv6: [::1]:3307:[::1]:3306\n",
            "  CLI -J overrides config ProxyJump. Jump chain rebuilds on reconnect.\n",
            "  -P password applies only to the final SSH host; use keys for ProxyJump hops.\n",
            "  --strict-host-keys: refuse unknown host keys (default: accept-new).\n",
            "  -L ports stay open during reconnect; new clients wait up to ~120s."
        )
    )]
    Ssh(SshCli),
}

#[derive(Args)]
struct BridgeCli {
    /// Where clients connect (local listener)
    #[arg(long, value_name = "ENDPOINT")]
    to: String,

    /// Upstream endpoint dialed for each accepted connection
    #[arg(long, value_name = "ENDPOINT")]
    from: String,

    /// Bearer token for WebSocket authorization
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
}

#[derive(Args)]
struct SshCli {
    /// Local forward (repeatable). [bind_host:]bind_port:remote_host:remote_port
    #[arg(
        short = 'L',
        long = "local-forward",
        value_name = "SPEC",
        action = clap::ArgAction::Append
    )]
    local_forwards: Vec<String>,

    /// Remote forward (repeatable). [bind_host:]bind_port:remote_host:remote_port
    #[arg(
        short = 'R',
        long = "remote-forward",
        value_name = "SPEC",
        action = clap::ArgAction::Append
    )]
    remote_forwards: Vec<String>,

    /// SSH host or ~/.ssh/config host alias
    ssh_host: String,

    /// Jump host(s), comma-separated or repeat -J. Overrides ~/.ssh/config ProxyJump
    #[arg(
        short = 'J',
        long = "jump",
        value_name = "HOST",
        action = clap::ArgAction::Append
    )]
    proxy_jump: Vec<String>,

    /// SSH username (overrides ~/.ssh/config)
    #[arg(short, long)]
    pub user: Option<String>,

    /// SSH password for password authentication
    #[arg(short = 'P', long)]
    pub password: Option<String>,

    /// SSH private key file (overrides ~/.ssh/config identity files)
    #[arg(short = 'i', long)]
    pub identity: Option<String>,

    /// SSH port (overrides ~/.ssh/config)
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Reject unknown host keys instead of adding them to ~/.ssh/known_hosts
    #[arg(long)]
    strict_host_keys: bool,
}

#[derive(Debug)]
pub enum Command {
    Bridge(BridgeArgs),
    Ssh(SshArgs),
}

#[derive(Debug)]
pub struct BridgeArgs {
    pub to: BridgeEndpoint,
    pub from: BridgeEndpoint,
    pub token: Option<String>,
}

#[derive(Debug)]
pub enum BridgeEndpoint {
    Tcp(TcpEndpoint),
    Ws(WebSocketEndpoint),
    Wss(WebSocketEndpoint),
}

#[derive(Debug, Clone)]
pub struct TcpEndpoint {
    pub addr: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct WebSocketEndpoint {
    pub url: String,
    pub bind_addr: String,
    pub path: String,
}

#[derive(Debug)]
pub struct SshArgs {
    pub forwards: Vec<SshForward>,
    pub ssh_host: String,
    pub proxy_jump: Vec<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub identity: Option<String>,
    pub port: Option<u16>,
    pub strict_host_keys: bool,
}

pub fn parse() -> Result<Command> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Bridge(args) => parse_bridge(args).map(Command::Bridge),
        CliCommand::Ssh(args) => parse_ssh(args).map(Command::Ssh),
    }
}

fn parse_bridge(cli: BridgeCli) -> Result<BridgeArgs> {
    let to = parse_bridge_to_endpoint(&cli.to)?;
    let from = parse_bridge_from_endpoint(&cli.from)?;

    match (&to, &from) {
        (BridgeEndpoint::Tcp(_), BridgeEndpoint::Tcp(_)) => {
            if cli.token.is_some() {
                bail!(
                    "--token is only supported when a WebSocket endpoint is used"
                );
            }
            Ok(BridgeArgs {
                to,
                from,
                token: None,
            })
        }
        (BridgeEndpoint::Tcp(_), BridgeEndpoint::Ws(_))
        | (BridgeEndpoint::Tcp(_), BridgeEndpoint::Wss(_))
        | (BridgeEndpoint::Ws(_), BridgeEndpoint::Tcp(_)) => Ok(BridgeArgs {
            to,
            from,
            token: cli.token,
        }),
        _ => bail!(
            "bridge currently supports --to tcp://... --from tcp://..., --to tcp://... --from ws(s)://..., or --to ws/http://... --from tcp://..."
        ),
    }
}

fn parse_bridge_to_endpoint(raw: &str) -> Result<BridgeEndpoint> {
    let url = parse_endpoint_url(raw)?;

    match url.scheme() {
        "tcp" => Ok(BridgeEndpoint::Tcp(parse_tcp_endpoint(raw, &url)?)),
        "ws" => Ok(BridgeEndpoint::Ws(parse_websocket_endpoint(&url, false)?)),
        "http" => Ok(BridgeEndpoint::Ws(parse_websocket_endpoint(
            &with_scheme(url, "ws")?,
            false,
        )?)),
        "wss" | "https" => bail!(
            "wss/https --to endpoints require TLS server support and are not supported yet"
        ),
        scheme => bail!(
            "Unsupported --to endpoint scheme '{scheme}': currently supports only tcp://, ws://, and http://"
        ),
    }
}

fn parse_bridge_from_endpoint(raw: &str) -> Result<BridgeEndpoint> {
    let url = parse_endpoint_url(raw)?;

    match url.scheme() {
        "tcp" => Ok(BridgeEndpoint::Tcp(parse_tcp_endpoint(raw, &url)?)),
        "ws" => Ok(BridgeEndpoint::Ws(parse_websocket_endpoint(&url, true)?)),
        "wss" => Ok(BridgeEndpoint::Wss(parse_websocket_endpoint(&url, true)?)),
        "http" => Ok(BridgeEndpoint::Ws(parse_websocket_endpoint(
            &with_scheme(url, "ws")?,
            true,
        )?)),
        "https" => Ok(BridgeEndpoint::Wss(parse_websocket_endpoint(
            &with_scheme(url, "wss")?,
            true,
        )?)),
        scheme => bail!(
            "Unsupported --from endpoint scheme '{scheme}': currently supports only tcp://, ws://, wss://, http://, and https://"
        ),
    }
}

fn parse_endpoint_url(raw: &str) -> Result<Url> {
    Url::parse(raw).with_context(|| format!("Invalid endpoint URL '{raw}'"))
}

fn with_scheme(mut url: Url, scheme: &str) -> Result<Url> {
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("Invalid endpoint scheme '{scheme}'"))?;
    Ok(url)
}

fn parse_tcp_endpoint(raw: &str, url: &Url) -> Result<TcpEndpoint> {
    validate_url_common(raw, url)?;

    if !matches!(url.path(), "" | "/") || url.query().is_some() {
        bail!("Invalid TCP endpoint '{raw}': expected tcp://host:port");
    }

    let host = url
        .host_str()
        .ok_or_else(|| {
            anyhow::anyhow!("Invalid endpoint '{raw}': host is required")
        })?
        .to_string();
    let port = url.port().ok_or_else(|| {
        anyhow::anyhow!("Invalid endpoint '{raw}': port is required")
    })?;

    Ok(TcpEndpoint {
        addr: url_host_port(raw, url, false)?,
        host,
        port,
    })
}

fn parse_websocket_endpoint(
    url: &Url,
    allow_query: bool,
) -> Result<WebSocketEndpoint> {
    validate_url_common(url.as_str(), url)?;

    if !allow_query && url.query().is_some() {
        bail!("Invalid --to endpoint '{}': query is not supported", url);
    }

    Ok(WebSocketEndpoint {
        url: url.as_str().to_string(),
        bind_addr: url_host_port(url.as_str(), url, true)?,
        path: url_path(url),
    })
}

fn validate_url_common(raw: &str, url: &Url) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() {
        bail!("Invalid endpoint '{raw}': user info is not supported");
    }

    if url.fragment().is_some() {
        bail!("Invalid endpoint '{raw}': fragments are not supported");
    }

    if url.host_str().is_none() {
        bail!("Invalid endpoint '{raw}': host is required");
    }

    Ok(())
}

fn url_host_port(
    raw: &str,
    url: &Url,
    allow_default_port: bool,
) -> Result<String> {
    let host = url.host_str().ok_or_else(|| {
        anyhow::anyhow!("Invalid endpoint '{raw}': host is required")
    })?;
    let port = if allow_default_port {
        url.port_or_known_default()
    } else {
        url.port()
    }
    .ok_or_else(|| {
        anyhow::anyhow!("Invalid endpoint '{raw}': port is required")
    })?;

    if host.contains(':') && !host.starts_with('[') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn url_path(url: &Url) -> String {
    if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    }
}

fn parse_ssh(cli: SshCli) -> Result<SshArgs> {
    if cli.local_forwards.is_empty() && cli.remote_forwards.is_empty() {
        bail!("at least one -L or -R forward is required");
    }

    let mut forwards = Vec::new();
    let mut seen_local = std::collections::HashSet::<(String, u16)>::new();
    let mut seen_remote = std::collections::HashSet::<(String, u16)>::new();

    for spec in &cli.local_forwards {
        let fwd = SshForward::parse(spec, ForwardKind::Local)?;
        let key = (fwd.bind_host.clone(), fwd.bind_port);
        if !seen_local.insert(key) {
            bail!(
                "duplicate local forward (-L) bind address {}",
                SshForward::socket_addr(&fwd.bind_host, fwd.bind_port)
            );
        }
        forwards.push(fwd);
    }
    for spec in &cli.remote_forwards {
        let fwd = SshForward::parse(spec, ForwardKind::Remote)?;
        if fwd.bind_port != 0 {
            let key = (fwd.bind_host.clone(), fwd.bind_port);
            if !seen_remote.insert(key) {
                bail!(
                    "duplicate remote forward (-R) bind address {}",
                    SshForward::socket_addr(&fwd.bind_host, fwd.bind_port)
                );
            }
        }
        forwards.push(fwd);
    }

    Ok(SshArgs {
        forwards,
        ssh_host: cli.ssh_host,
        proxy_jump: cli.proxy_jump,
        user: cli.user,
        password: cli.password,
        identity: cli.identity,
        port: cli.port,
        strict_host_keys: cli.strict_host_keys,
    })
}
