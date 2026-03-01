//! Application configuration - loads settings from config.json.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::info;

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Proxy server listen port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Path to the rules JSON file
    #[serde(default = "default_rules_file", rename = "rulesFile")]
    pub rules_file: String,

    /// Web dashboard listen port
    #[serde(default = "default_web_port", rename = "webPort")]
    pub web_port: u16,

    /// Whether to auto-open browser on start
    #[serde(default = "default_true", rename = "autoOpenBrowser")]
    pub auto_open_browser: bool,

    /// Whether to auto-set system proxy
    #[serde(default, rename = "systemProxy")]
    pub system_proxy: bool,

    /// Global upstream proxy URL
    #[serde(default, rename = "upstreamProxy")]
    pub upstream_proxy: Option<String>,
}

fn default_port() -> u16 {
    8888
}
fn default_rules_file() -> String {
    "rules.json".to_string()
}
fn default_web_port() -> u16 {
    9000
}
fn default_true() -> bool {
    true
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            rules_file: default_rules_file(),
            web_port: default_web_port(),
            auto_open_browser: true,
            system_proxy: false,
            upstream_proxy: None,
        }
    }
}

/// Thread-safe config manager that supports reading and saving config.
pub struct ConfigManager {
    config: RwLock<AppConfig>,
    config_path: PathBuf,
}

impl ConfigManager {
    /// Load config from file. If file doesn't exist, create with defaults.
    pub fn load(config_path: &Path) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let config = if config_path.exists() {
            let content = fs::read_to_string(config_path)?;
            let cfg: AppConfig = serde_json::from_str(&content)?;
            info!("[Config] Loaded from {}", config_path.display());
            cfg
        } else {
            let cfg = AppConfig::default();
            let content = serde_json::to_string_pretty(&cfg)?;
            fs::write(config_path, content)?;
            info!(
                "[Config] Created default config at {}",
                config_path.display()
            );
            cfg
        };

        Ok(Arc::new(Self {
            config: RwLock::new(config),
            config_path: config_path.to_path_buf(),
        }))
    }

    /// Get a snapshot of the current config.
    pub fn get(&self) -> AppConfig {
        self.config.read().unwrap().clone()
    }

    /// Update config and save to file.
    pub fn update(
        &self,
        new_config: AppConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = serde_json::to_string_pretty(&new_config)?;
        fs::write(&self.config_path, &content)?;
        let mut cfg = self.config.write().unwrap();
        *cfg = new_config;
        info!("[Config] Saved to {}", self.config_path.display());
        Ok(())
    }

    /// Get the resolved rules file path (relative to config file's directory).
    pub fn rules_path(&self) -> PathBuf {
        let cfg = self.config.read().unwrap();
        let rules_file = PathBuf::from(&cfg.rules_file);
        if rules_file.is_absolute() {
            rules_file
        } else {
            self.config_path
                .parent()
                .unwrap_or(Path::new("."))
                .join(rules_file)
        }
    }

    /// Get the config file path.
    #[allow(dead_code)]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}
