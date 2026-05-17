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
            "SUPPORTED ENDPOINTS:\n",
            "  --export  tcp://host:port, ws://host:port/path, or http://host:port/path\n",
            "  --import  tcp://host:port, ws://host:port/path, wss://host:port/path, http://host:port/path, or https://host:port/path\n",
            "  --token   optional bearer token for WebSocket export/import authorization\n",
            "\n",
            "NOTES:\n",
            "  --export is the local endpoint exposed by weconn\n",
            "  --import is the endpoint weconn connects to for each accepted connection\n",
            "  tcp:// export with tcp:// import performs direct TCP forwarding\n",
            "  http:// export/import endpoints are treated as ws:// WebSocket endpoints over HTTP Upgrade\n",
            "  https:// import endpoints are treated as wss://\n",
            "  wss:// and https:// export endpoints are not supported yet\n",
            "  export WebSocket paths are enforced during the handshake\n",
            "  --token is checked from Authorization: Bearer <token> or ?token=<token> on export\n",
            "  --token is sent as Authorization: Bearer <token> on WebSocket import\n",
            "\n",
            "EXAMPLES:\n",
            "  weconn bridge --export tcp://127.0.0.1:8080 --import tcp://127.0.0.1:80\n",
            "  weconn bridge --export tcp://127.0.0.1:3306 --import https://public.com:443/wss\n",
            "  weconn bridge --export tcp://127.0.0.1:3307 --import wss://public.com:443/wss\n",
            "  weconn bridge --export tcp://127.0.0.1:3307 --import ws://public.com:8080/wss\n",
            "  weconn bridge --export http://0.0.0.0:8080/wss --import tcp://mysql:3306\n",
            "  weconn bridge --export ws://0.0.0.0:8080/wss --import tcp://mysql:3306\n",
            "  weconn bridge --export http://0.0.0.0:8080/mysql --import tcp://internal.com:3306\n",
            "  weconn bridge --export http://0.0.0.0:8080/mysql --import tcp://mysql:3306 --token secret"
        )
    )]
    Bridge(BridgeCli),

    #[command(
        about = "Stable SSH port forwarding with auto-reconnect",
        long_about = concat!(
            "weconn ssh creates SSH tunnels that automatically reconnect on network failures.\n",
            "Forward syntax matches OpenSSH -L and -R.\n",
            "\n",
            "FORWARD SPEC:\n",
            "  [bind_address:]port:host:hostport\n",
            "  IPv6 must use brackets: [::1]:3307:[::1]:3306\n",
            "\n",
            "  -L  Local forward: listen on this machine, connect from the SSH server\n",
            "  -R  Remote forward: listen on the SSH server, connect on this machine\n",
            "\n",
            "EXAMPLES:\n",
            "  weconn ssh -L 3307:10.0.0.5:3306 myserver\n",
            "  weconn ssh -L 127.0.0.1:3307:10.0.0.5:3306 myserver\n",
            "  weconn ssh -L [::1]:3307:[2001:db8::1]:3306 myserver\n",
            "  weconn ssh -R 8080:127.0.0.1:3000 myserver\n",
            "  weconn ssh -L 3307:db:3306 -R 8080:127.0.0.1:3000 myserver"
        )
    )]
    Ssh(SshCli),
}

#[derive(Args)]
struct BridgeCli {
    /// Local endpoint exported by weconn
    #[arg(long, value_name = "ENDPOINT")]
    export: String,

    /// Endpoint imported by weconn for each accepted connection
    #[arg(long, value_name = "ENDPOINT")]
    import: String,

    /// Bearer token for WebSocket export/import authorization
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
}

#[derive(Args)]
struct SshCli {
    /// Local forward: [bind_address:]port:host:hostport (same as ssh -L)
    #[arg(
        short = 'L',
        long = "local-forward",
        value_name = "SPEC",
        action = clap::ArgAction::Append
    )]
    local_forwards: Vec<String>,

    /// Remote forward: [bind_address:]port:host:hostport (same as ssh -R)
    #[arg(
        short = 'R',
        long = "remote-forward",
        value_name = "SPEC",
        action = clap::ArgAction::Append
    )]
    remote_forwards: Vec<String>,

    /// SSH host or ~/.ssh/config host alias
    ssh_host: String,

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
}

#[derive(Debug)]
pub enum Command {
    Bridge(BridgeArgs),
    Ssh(SshArgs),
}

#[derive(Debug)]
pub struct BridgeArgs {
    pub export: BridgeEndpoint,
    pub import: BridgeEndpoint,
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
    pub user: Option<String>,
    pub password: Option<String>,
    pub identity: Option<String>,
    pub port: Option<u16>,
}

pub fn parse() -> Result<Command> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Bridge(args) => parse_bridge(args).map(Command::Bridge),
        CliCommand::Ssh(args) => parse_ssh(args).map(Command::Ssh),
    }
}

fn parse_bridge(cli: BridgeCli) -> Result<BridgeArgs> {
    let export = parse_bridge_export_endpoint(&cli.export)?;
    let import = parse_bridge_import_endpoint(&cli.import)?;

    match (&export, &import) {
        (BridgeEndpoint::Tcp(_), BridgeEndpoint::Tcp(_)) => {
            if cli.token.is_some() {
                bail!(
                    "--token is only supported when a WebSocket endpoint is used"
                );
            }
            Ok(BridgeArgs {
                export,
                import,
                token: None,
            })
        }
        (BridgeEndpoint::Tcp(_), BridgeEndpoint::Ws(_))
        | (BridgeEndpoint::Tcp(_), BridgeEndpoint::Wss(_))
        | (BridgeEndpoint::Ws(_), BridgeEndpoint::Tcp(_)) => Ok(BridgeArgs {
            export,
            import,
            token: cli.token,
        }),
        _ => bail!(
            "bridge currently supports --export tcp://... --import tcp://..., --export tcp://... --import ws(s)://..., or --export ws/http://... --import tcp://..."
        ),
    }
}

fn parse_bridge_export_endpoint(raw: &str) -> Result<BridgeEndpoint> {
    let url = parse_endpoint_url(raw)?;

    match url.scheme() {
        "tcp" => Ok(BridgeEndpoint::Tcp(parse_tcp_endpoint(raw, &url)?)),
        "ws" => Ok(BridgeEndpoint::Ws(parse_websocket_endpoint(&url, false)?)),
        "http" => Ok(BridgeEndpoint::Ws(parse_websocket_endpoint(
            &with_scheme(url, "ws")?,
            false,
        )?)),
        "wss" | "https" => bail!(
            "wss/https export endpoints require TLS server support and are not supported yet"
        ),
        scheme => bail!(
            "Unsupported export endpoint scheme '{scheme}': currently supports only tcp://, ws://, and http://"
        ),
    }
}

fn parse_bridge_import_endpoint(raw: &str) -> Result<BridgeEndpoint> {
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
            "Unsupported import endpoint scheme '{scheme}': currently supports only tcp://, ws://, wss://, http://, and https://"
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
        bail!("Invalid export endpoint '{}': query is not supported", url);
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
    for spec in &cli.local_forwards {
        forwards.push(SshForward::parse(spec, ForwardKind::Local)?);
    }
    for spec in &cli.remote_forwards {
        forwards.push(SshForward::parse(spec, ForwardKind::Remote)?);
    }

    Ok(SshArgs {
        forwards,
        ssh_host: cli.ssh_host,
        user: cli.user,
        password: cli.password,
        identity: cli.identity,
        port: cli.port,
    })
}
