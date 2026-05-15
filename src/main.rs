use anyhow::Result;
use tracing_subscriber::EnvFilter;

mod cli;
mod client;
mod ssh_config;
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
        cli::Command::Ssh(args) => tunnel::run(args).await,
    }
}
