use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};

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
    Ssh(SshArgs),
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
        CliCommand::Ssh(args) => parse_ssh(args).map(Command::Ssh),
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
