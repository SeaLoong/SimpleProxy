//! Rule engine - loads, watches, and matches proxy rules from a JSON file.
//!
//! Rules file is a plain JSON array of rule objects.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{error, info, warn};

/// A single proxy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Rule {
    /// Optional comment describing the rule
    #[serde(default)]
    pub comment: Option<String>,

    /// URL pattern to match (exact string or regex)
    pub r#match: String,

    /// Whether `match` is a regex pattern
    #[serde(default, rename = "isRegex")]
    pub is_regex: bool,

    /// Rule type: redirect, replace, block, proxy, forward
    pub r#type: String,

    /// Target URL (for redirect / proxy types)
    #[serde(default)]
    pub target: Option<String>,

    /// HTTP status code to return
    #[serde(default, rename = "statusCode")]
    pub status_code: Option<u16>,

    /// Response body content
    #[serde(default)]
    pub body: Option<String>,

    /// Content-Type header (for replace type)
    #[serde(default, rename = "contentType")]
    pub content_type: Option<String>,

    /// Path to a local file whose content will be returned (for replace type)
    #[serde(default)]
    pub file: Option<String>,

    /// Custom headers to inject
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,

    /// Whether the rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Upstream proxy URL (for forward type)
    #[serde(default, rename = "upstreamProxy")]
    pub upstream_proxy: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Compiled rule with pre-compiled regex.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: Rule,
    pub regex: Option<Regex>,
}

/// Thread-safe inner state of the rule engine.
struct RuleEngineInner {
    rules: Vec<CompiledRule>,
    raw_rules: Vec<Rule>,
}

/// Rule engine: loads rules from JSON, supports hot-reload and matching.
pub struct RuleEngine {
    inner: RwLock<RuleEngineInner>,
    rules_path: PathBuf,
}

impl RuleEngine {
    /// Create a new RuleEngine and load rules from the given path.
    pub fn new(rules_path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let engine = Self {
            inner: RwLock::new(RuleEngineInner {
                rules: Vec::new(),
                raw_rules: Vec::new(),
            }),
            rules_path: rules_path.to_path_buf(),
        };
        engine.load()?;
        Ok(engine)
    }

    /// Load (or reload) rules from the JSON file.
    pub fn load(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = fs::read_to_string(&self.rules_path)?;
        let raw_rules: Vec<Rule> = serde_json::from_str(&content)?;

        let enabled_rules: Vec<CompiledRule> = raw_rules
            .iter()
            .filter(|r| r.enabled)
            .map(|rule| {
                let regex = if rule.is_regex {
                    match Regex::new(&rule.r#match) {
                        Ok(re) => Some(re),
                        Err(e) => {
                            warn!("Invalid regex '{}': {}", rule.r#match, e);
                            None
                        }
                    }
                } else {
                    None
                };
                CompiledRule {
                    rule: rule.clone(),
                    regex,
                }
            })
            .collect();

        let total = enabled_rules.len();
        info!("[RuleEngine] Loaded {} enabled rules", total);

        let mut inner = self.inner.write().unwrap();
        inner.rules = enabled_rules;
        inner.raw_rules = raw_rules;

        Ok(())
    }

    /// Match a full URL against the loaded rules. Returns the first matching rule.
    pub fn match_url(&self, full_url: &str) -> Option<Rule> {
        let inner = self.inner.read().unwrap();
        for compiled in &inner.rules {
            if compiled.rule.is_regex {
                if let Some(ref re) = compiled.regex {
                    if re.is_match(full_url) {
                        return Some(compiled.rule.clone());
                    }
                }
            } else if full_url == compiled.rule.r#match {
                return Some(compiled.rule.clone());
            }
        }
        None
    }

    /// Get a copy of all raw rules (for the web API).
    pub fn get_rules(&self) -> Vec<Rule> {
        self.inner.read().unwrap().raw_rules.clone()
    }

    /// Replace all rules and save to disk.
    pub fn set_rules(&self, rules: Vec<Rule>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = serde_json::to_string_pretty(&rules)?;
        fs::write(&self.rules_path, content)?;
        // Reload from the freshly-written file to re-compile regexes
        self.load()
    }

    /// Read a local file referenced by a rule's `file` field.
    pub fn read_local_file(&self, rule: &Rule) -> Result<Vec<u8>, std::io::Error> {
        let file_path_str = rule.file.as_deref().unwrap_or("");
        let file_path = self.rules_path.parent().unwrap().join(file_path_str);
        fs::read(&file_path)
    }
}

/// Start a file watcher that automatically reloads rules on changes.
pub fn start_watcher(
    engine: Arc<RuleEngine>,
    rules_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use notify::{Event, EventKind, RecursiveMode, Watcher};

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();

    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(
        rules_path.parent().unwrap_or(Path::new(".")),
        RecursiveMode::NonRecursive,
    )?;

    let rules_filename = rules_path
        .file_name()
        .unwrap_or_default()
        .to_os_string();

    std::thread::spawn(move || {
        let _watcher = watcher; // Keep watcher alive
        let mut last_reload = std::time::Instant::now();
        let debounce_duration = Duration::from_millis(300);

        for event in rx {
            match event {
                Ok(Event {
                    kind: EventKind::Modify(_) | EventKind::Create(_),
                    paths,
                    ..
                }) => {
                    let matches = paths.iter().any(|p| {
                        p.file_name()
                            .map(|n| n == rules_filename)
                            .unwrap_or(false)
                    });
                    if matches && last_reload.elapsed() >= debounce_duration {
                        info!("[RuleEngine] Rules file changed, reloading...");
                        if let Err(e) = engine.load() {
                            error!("[RuleEngine] Failed to reload rules: {}", e);
                        }
                        last_reload = std::time::Instant::now();
                    }
                }
                Err(e) => {
                    error!("[Watcher] Error: {}", e);
                }
                _ => {}
            }
        }
    });

    Ok(())
}
