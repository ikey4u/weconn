use anyhow::Result;
use tracing_subscriber::EnvFilter;

mod bridge;
mod cli;
mod client;
mod ssh_config;
mod ssh_forward;
mod ssh_session;
mod tunnel;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match cli::parse()? {
        cli::Command::Bridge(args) => bridge::run(args).await,
        cli::Command::Ssh(args) => tunnel::run(args).await,
    }
}
