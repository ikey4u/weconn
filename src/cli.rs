use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use url::Url;

#[derive(Debug, Clone)]
pub struct ForwardSpec {
    pub bind_host: String,
    pub bind_port: u16,
    pub dest_host: String,
    pub dest_port: u16,
}

impl ForwardSpec {
    pub fn parse(s: &str) -> Result<Self> {
        let (kind_str, rest) = s.split_once('/').ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid rule '{s}': expected l/bind:port/dest:port"
            )
        })?;

        let is_remote_pull = match kind_str {
            "l" | "L" => false,
            "r" | "R" => true,
            _ => bail!(
                "Invalid type '{kind_str}' in '{s}': must be 'l' (local) or 'r' (remote)"
            ),
        };

        let (first_part, second_part) =
            rest.split_once('/').ok_or_else(|| {
                anyhow::anyhow!("Invalid rule '{s}': missing second address")
            })?;

        let (first_host, first_port) =
            parse_host_port(first_part).map_err(|e| {
                anyhow::anyhow!("Invalid first address in '{s}': {e}")
            })?;
        let (second_host, second_port) =
            parse_host_port(second_part).map_err(|e| {
                anyhow::anyhow!("Invalid second address in '{s}': {e}")
            })?;

        // Both l/ and r/ produce SSH -L style forwarding (local listener, SSH server connects
        // to the remote service). They differ only in argument order:
        //   l/local_bind/remote_service  → listen locally at local_bind
        //   r/remote_service/local_bind  → same, but remote service is listed first
        let (bind_host, bind_port, dest_host, dest_port) = if is_remote_pull {
            // r: first arg = remote service, second arg = local bind
            (second_host, second_port, first_host, first_port)
        } else {
            // l: first arg = local bind, second arg = remote service
            (first_host, first_port, second_host, second_port)
        };

        Ok(ForwardSpec {
            bind_host,
            bind_port,
            dest_host,
            dest_port,
        })
    }
}

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    match s.rfind(':') {
        Some(pos) => {
            let host = &s[..pos];
            let port: u16 = s[pos + 1..]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port number"))?;
            let host = normalize_host(host);
            Ok((host, port))
        }
        None => {
            let port: u16 = s.parse().map_err(|_| {
                anyhow::anyhow!("expected host:port or port, got '{s}'")
            })?;
            Ok(("127.0.0.1".to_string(), port))
        }
    }
}

/// Normalize shorthand host forms:
///   ""  → "127.0.0.1"   (:8080  means listen on localhost only)
///   "0" → "0.0.0.0"     (0:8080 means listen on all interfaces)
fn normalize_host(h: &str) -> String {
    match h {
        "" | "localhost" => "127.0.0.1".to_string(),
        "0" => "0.0.0.0".to_string(),
        other => other.to_string(),
    }
}

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
        about = "Bridge TCP streams over WebSocket",
        long_about = concat!(
            "weconn bridge converts TCP streams to WebSocket streams, or WebSocket streams to TCP.\n",
            "\n",
            "SUPPORTED ENDPOINTS:\n",
            "  --export  tcp://host:port, ws://host:port/path, or http://host:port/path\n",
            "  --import  tcp://host:port, ws://host:port/path, wss://host:port/path, http://host:port/path, or https://host:port/path\n",
            "  --token   optional bearer token for WebSocket export/import authorization\n",
            "\n",
            "NOTES:\n",
            "  --export is the local endpoint exposed by weconn\n",
            "  --import is the endpoint weconn connects to for each accepted connection\n",
            "  http:// export/import endpoints are treated as ws:// WebSocket endpoints over HTTP Upgrade\n",
            "  https:// import endpoints are treated as wss://\n",
            "  wss:// and https:// export endpoints are not supported yet\n",
            "  export WebSocket paths are enforced during the handshake\n",
            "  --token is checked from Authorization: Bearer <token> or ?token=<token> on export\n",
            "  --token is sent as Authorization: Bearer <token> on WebSocket import\n",
            "\n",
            "EXAMPLES:\n",
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
            "\n",
            "RULES (both are SSH -L; only argument order differs):\n",
            "  l/local_bind/remote_service   Listen at local_bind, SSH server connects to remote_service\n",
            "  r/remote_service/local_bind   Same effect, remote service address listed first\n",
            "\n",
            "ADDRESS SHORTHANDS:\n",
            "  3306          →  127.0.0.1:3306\n",
            "  :3306         →  127.0.0.1:3306\n",
            "  0:3306        →  0.0.0.0:3306\n",
            "\n",
            "EXAMPLES:\n",
            "  weconn ssh l/3307/10.0.0.5:3306 myserver\n",
            "  weconn ssh r/10.0.0.5:3306/3307 myserver\n",
            "  weconn ssh l/3307/10.0.0.5:3306 r/8080/api:80 myserver"
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
    /// Forward rules and SSH host (host is the last argument)
    /// e.g.: l/127.0.0.1:3307/10.0.0.5:3306  r/0.0.0.0:8080/127.0.0.1:8080  myserver
    #[arg(required = true, num_args = 2..)]
    args: Vec<String>,

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
}

#[derive(Debug, Clone)]
pub struct WebSocketEndpoint {
    pub url: String,
    pub bind_addr: String,
    pub path: String,
}

#[derive(Debug)]
pub struct SshArgs {
    pub specs: Vec<ForwardSpec>,
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
        (BridgeEndpoint::Tcp(_), BridgeEndpoint::Ws(_))
        | (BridgeEndpoint::Tcp(_), BridgeEndpoint::Wss(_))
        | (BridgeEndpoint::Ws(_), BridgeEndpoint::Tcp(_)) => Ok(BridgeArgs {
            export,
            import,
            token: cli.token,
        }),
        _ => bail!(
            "bridge currently supports --export tcp://... --import ws(s)://... or --export ws/http://... --import tcp://..."
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

    Ok(TcpEndpoint {
        addr: url_host_port(raw, url, false)?,
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
    let mut args = cli.args;
    let ssh_host = args.pop().expect("clap ensures at least 2 args");

    if args.is_empty() {
        bail!("At least one forward rule is required before the SSH host");
    }

    let specs = args
        .iter()
        .map(|s| ForwardSpec::parse(s))
        .collect::<Result<Vec<_>>>()?;

    Ok(SshArgs {
        specs,
        ssh_host,
        user: cli.user,
        password: cli.password,
        identity: cli.identity,
        port: cli.port,
    })
}
