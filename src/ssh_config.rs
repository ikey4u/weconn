use std::path::{Path, PathBuf};

use tracing::debug;

#[derive(Debug, Clone)]
pub struct HostConfig {
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
}

pub fn resolve(
    host: &str,
    port_override: Option<u16>,
    user_override: Option<&str>,
    identity_override: Option<&str>,
) -> HostConfig {
    let mut config = HostConfig {
        hostname: host.to_string(),
        port: 22,
        user: current_user(),
        identity_files: default_identity_files(),
    };

    if let Some(home) = dirs::home_dir() {
        let ssh_config_path = home.join(".ssh").join("config");
        if ssh_config_path.exists() {
            if let Err(e) =
                apply_ssh_config(&mut config, host, &ssh_config_path)
            {
                debug!("SSH config parse error: {e}");
            }
        }
    }

    if let Some(port) = port_override {
        config.port = port;
    }
    if let Some(user) = user_override {
        config.user = user.to_string();
    }
    if let Some(identity) = identity_override {
        config.identity_files = vec![PathBuf::from(identity)];
    }

    debug!(
        hostname = %config.hostname,
        port = config.port,
        user = %config.user,
        ?config.identity_files,
        "Resolved SSH host config"
    );

    config
}

fn apply_ssh_config(
    config: &mut HostConfig,
    host: &str,
    path: &Path,
) -> anyhow::Result<()> {
    use std::{fs::File, io::BufReader};

    use ssh2_config::{ParseRule, SshConfig};

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let ssh_config = SshConfig::default()
        .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)?;

    let params = ssh_config.query(host);

    if let Some(hostname) = params.host_name {
        config.hostname = hostname;
    }
    if let Some(port) = params.port {
        config.port = port;
    }
    if let Some(user) = params.user {
        config.user = user;
    }
    if let Some(identity_files) = params.identity_file {
        if !identity_files.is_empty() {
            config.identity_files =
                identity_files.into_iter().map(expand_tilde).collect();
        }
    }

    Ok(())
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    if let Some(s) = path.to_str() {
        if let Some(rest) = s.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(rest);
            }
        }
    }
    path
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

fn default_identity_files() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return vec![];
    };
    let ssh_dir = home.join(".ssh");
    ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"]
        .iter()
        .map(|name| ssh_dir.join(name))
        .filter(|p| p.exists())
        .collect()
}
