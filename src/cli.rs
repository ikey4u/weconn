use anyhow::{Result, bail};
use clap::Parser;

#[derive(Debug, Clone, PartialEq)]
pub enum ForwardKind {
    Local,
    Remote,
}

#[derive(Debug, Clone)]
pub struct ForwardSpec {
    pub kind: ForwardKind,
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

        let kind = match kind_str {
            "l" | "L" => ForwardKind::Local,
            "r" | "R" => ForwardKind::Remote,
            _ => bail!(
                "Invalid type '{kind_str}' in '{s}': must be 'l' (local) or 'r' (remote)"
            ),
        };

        let (bind_part, dest_part) = rest
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("Invalid rule '{s}': missing dest, expected l/bind:port/dest:port"))?;

        let (bind_host, bind_port) =
            parse_host_port(bind_part).map_err(|e| {
                anyhow::anyhow!("Invalid bind address in '{s}': {e}")
            })?;
        let (dest_host, dest_port) =
            parse_host_port(dest_part).map_err(|e| {
                anyhow::anyhow!("Invalid dest address in '{s}': {e}")
            })?;

        Ok(ForwardSpec {
            kind,
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
    about = "Stable SSH port forwarding with auto-reconnect",
    long_about = concat!(
        "weconn creates SSH tunnels that automatically reconnect on network failures.\n",
        "\n",
        "RULES:\n",
        "  l/bind:port/dest:port   Local: listen locally, forward to dest via SSH\n",
        "  r/bind:port/dest:port   Remote: SSH server listens, forward to local dest\n",
        "\n",
        "EXAMPLES:\n",
        "  weconn l/127.0.0.1:3307/10.0.0.5:3306 myserver\n",
        "  weconn r/0.0.0.0:8080/127.0.0.1:8080 myserver\n",
        "  weconn l/3307/10.0.0.5:3306 r/0.0.0.0:8080/127.0.0.1:8080 myserver"
    )
)]
struct Cli {
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
pub struct ParsedArgs {
    pub specs: Vec<ForwardSpec>,
    pub ssh_host: String,
    pub user: Option<String>,
    pub password: Option<String>,
    pub identity: Option<String>,
    pub port: Option<u16>,
}

pub fn parse() -> Result<ParsedArgs> {
    let cli = Cli::parse();
    let mut args = cli.args;

    let ssh_host = args.pop().expect("clap ensures at least 2 args");

    if args.is_empty() {
        bail!("At least one forward rule is required before the SSH host");
    }

    let specs = args
        .iter()
        .map(|s| ForwardSpec::parse(s))
        .collect::<Result<Vec<_>>>()?;

    Ok(ParsedArgs {
        specs,
        ssh_host,
        user: cli.user,
        password: cli.password,
        identity: cli.identity,
        port: cli.port,
    })
}
