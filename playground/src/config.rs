use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use base64::Engine;

use crate::error::{ArenaError, ArenaResult};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub database_path: PathBuf,
    pub public_base_url: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_owner: String,
    pub github_repo: String,
    pub github_app_id: u64,
    pub github_installation_id: u64,
    pub github_app_private_key_pem: String,
    pub mac_key_id: String,
    pub mac_keys: HashMap<String, Vec<u8>>,
    pub runner_socket: PathBuf,
    pub secure_cookies: bool,
    pub session_ttl_seconds: i64,
    pub source_limit_bytes: usize,
    pub queue_limit: i64,
}

impl Config {
    pub fn from_env() -> ArenaResult<Self> {
        let get = |name: &str| {
            std::env::var(name).map_err(|_| ArenaError::Configuration(format!("missing {name}")))
        };
        let listen = std::env::var("ARENA_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:8080".into())
            .parse()
            .map_err(|_| ArenaError::Configuration("invalid ARENA_LISTEN".into()))?;
        let mac_key_id =
            std::env::var("ARENA_MAC_KEY_ID").unwrap_or_else(|_| "arena-primary-v1".into());
        let mac_keys = load_mac_keys(&get, &mac_key_id)?;
        let public_base_url = get("ARENA_PUBLIC_BASE_URL")?;
        let secure_cookies = !public_base_url.starts_with("http://localhost")
            && !public_base_url.starts_with("http://127.0.0.1");

        let github_app_id = get("GITHUB_APP_ID")?
            .parse()
            .map_err(|_| ArenaError::Configuration("invalid GITHUB_APP_ID".into()))?;
        let github_installation_id = get("GITHUB_INSTALLATION_ID")?
            .parse()
            .map_err(|_| ArenaError::Configuration("invalid GITHUB_INSTALLATION_ID".into()))?;
        let private_key_path = get("GITHUB_APP_PRIVATE_KEY_PATH")?;
        let github_app_private_key_pem = std::fs::read_to_string(private_key_path)
            .map_err(|_| ArenaError::Configuration("cannot read GitHub App private key".into()))?;

        Ok(Self {
            listen,
            database_path: PathBuf::from(
                std::env::var("ARENA_DATABASE_PATH")
                    .unwrap_or_else(|_| "./data/arena.sqlite3".into()),
            ),
            public_base_url,
            github_client_id: get("GITHUB_CLIENT_ID")?,
            github_client_secret: get("GITHUB_CLIENT_SECRET")?,
            github_owner: get("GITHUB_OWNER")?,
            github_repo: get("GITHUB_REPO")?,
            github_app_id,
            github_installation_id,
            github_app_private_key_pem,
            mac_key_id,
            mac_keys,
            runner_socket: PathBuf::from(
                std::env::var("ARENA_RUNNER_SOCKET")
                    .unwrap_or_else(|_| "/run/coggate-playground/runner.sock".into()),
            ),
            secure_cookies,
            session_ttl_seconds: 30 * 24 * 60 * 60,
            source_limit_bytes: 32 * 1024,
            queue_limit: 20,
        })
    }

    pub fn github_callback_url(&self) -> String {
        format!(
            "{}/auth/github/callback",
            self.public_base_url.trim_end_matches('/')
        )
    }
}

#[derive(serde::Deserialize)]
struct KeyringFile {
    keys: HashMap<String, String>,
}

fn load_mac_keys(
    get: &impl Fn(&str) -> ArenaResult<String>,
    active_id: &str,
) -> ArenaResult<HashMap<String, Vec<u8>>> {
    let encoded = if let Ok(path) = std::env::var("ARENA_MAC_KEYRING_PATH") {
        let value = std::fs::read_to_string(path)
            .map_err(|_| ArenaError::Configuration("cannot read MAC keyring".into()))?;
        serde_json::from_str::<KeyringFile>(&value)
            .map_err(|_| ArenaError::Configuration("invalid MAC keyring JSON".into()))?
            .keys
    } else {
        HashMap::from([(active_id.to_owned(), get("ARENA_MAC_KEY_BASE64URL")?)])
    };
    let mut keys = HashMap::new();
    for (id, value) in encoded {
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ArenaError::Configuration("invalid MAC key encoding".into()))?;
        if id.is_empty() || key.len() < 32 {
            return Err(ArenaError::Configuration("invalid MAC key material".into()));
        }
        keys.insert(id, key);
    }
    if !keys.contains_key(active_id) {
        return Err(ArenaError::Configuration(
            "active MAC key is missing".into(),
        ));
    }
    Ok(keys)
}
