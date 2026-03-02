//! Certificate authority management for HTTPS MITM interception.
//!
//! On first run, generates a self-signed root CA certificate and key pair.
//! For each intercepted host, generates a leaf certificate signed by the CA.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

/// Manages CA certificate, key pair, and per-host certificate cache.
pub struct CertManager {
    /// The original CA certificate DER bytes (from disk, the one users trust)
    ca_cert_der: Vec<u8>,
    /// The CA key pair (loaded from disk)
    ca_key_pair: KeyPair,
    /// Cache of per-host TLS ServerConfig
    cache: RwLock<HashMap<String, Arc<ServerConfig>>>,
    ca_dir: PathBuf,
}

impl CertManager {
    /// Load or generate the CA certificate from `<config_dir>/ca/`.
    pub fn new(config_dir: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let ca_dir = config_dir.join("ca");
        fs::create_dir_all(&ca_dir)?;

        let cert_path = ca_dir.join("ca.crt");
        let key_path = ca_dir.join("ca.key");

        let (ca_cert_der, ca_key_pair) = if cert_path.exists() && key_path.exists() {
            info!(
                "[CertManager] Loading existing CA from {}",
                ca_dir.display()
            );
            let cert_pem = fs::read_to_string(&cert_path)?;
            let key_pem = fs::read_to_string(&key_path)?;
            let key_pair = KeyPair::from_pem(&key_pem)?;

            // Parse PEM → DER
            let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
            let der = certs
                .into_iter()
                .next()
                .ok_or("No certificate found in ca.crt")?
                .to_vec();

            (der, key_pair)
        } else {
            info!(
                "[CertManager] Generating new CA certificate in {}",
                ca_dir.display()
            );
            let (cert_pem, cert_der, key_pair) = generate_ca()?;
            fs::write(&cert_path, &cert_pem)?;
            fs::write(&key_path, key_pair.serialize_pem())?;
            info!(
                "[CertManager] CA certificate saved to {}",
                cert_path.display()
            );
            println!();
            println!("========================================");
            println!("  HTTPS interception: CA certificate generated");
            println!("  Please trust this CA certificate:");
            println!("  {}", cert_path.display());
            println!("========================================");
            println!();
            (cert_der, key_pair)
        };

        Ok(Self {
            ca_cert_der,
            ca_key_pair,
            cache: RwLock::new(HashMap::new()),
            ca_dir,
        })
    }

    /// Get the path to the CA certificate file.
    #[allow(dead_code)]
    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca_dir.join("ca.crt")
    }

    /// Get the CA certificate in PEM format (for download).
    pub fn ca_cert_pem(&self) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&self.ca_cert_der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for (i, c) in b64.chars().enumerate() {
            pem.push(c);
            if (i + 1) % 64 == 0 {
                pem.push('\n');
            }
        }
        if !pem.ends_with('\n') {
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    /// Get certificate status info as a JSON string for the web API.
    pub fn cert_status_json(&self) -> String {
        let trusted = is_ca_trusted(&self.ca_cert_der).unwrap_or_default();
        let path = self.ca_cert_path();
        format!(
            r#"{{"trusted":{},"certPath":"{}"}}"#,
            trusted,
            path.display().to_string().replace('\\', "\\\\")
        )
    }

    /// Get a `rustls::ServerConfig` for the given hostname.
    /// Caches the result so repeated requests reuse the same config.
    pub fn server_config_for_host(
        &self,
        hostname: &str,
    ) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(cfg) = cache.get(hostname) {
                return Ok(Arc::clone(cfg));
            }
        }

        // Generate a new leaf certificate for this host
        let leaf_cert = self.generate_leaf_cert(hostname)?;
        let cfg = Arc::new(leaf_cert);

        // Store in cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(hostname.to_string(), Arc::clone(&cfg));
        }

        Ok(cfg)
    }

    /// Generate a leaf (server) certificate for the given hostname, signed by our CA.
    fn generate_leaf_cert(
        &self,
        hostname: &str,
    ) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, hostname);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "SimpleProxy");

        // Set validity period
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 12, 31);

        // Add Subject Alternative Names
        if hostname.parse::<std::net::IpAddr>().is_ok() {
            params
                .subject_alt_names
                .push(SanType::IpAddress(hostname.parse().unwrap()));
        } else {
            params
                .subject_alt_names
                .push(SanType::DnsName(hostname.try_into()?));
        }

        params.is_ca = IsCa::NoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);

        // Generate a new key pair for the leaf certificate
        let leaf_key_pair = KeyPair::generate()?;

        // Create an Issuer from the CA params and key pair for signing
        let ca_params = create_ca_params();
        let issuer = Issuer::from_params(&ca_params, &self.ca_key_pair);
        let leaf_cert = params.signed_by(&leaf_key_pair, &issuer)?;

        // Build the rustls ServerConfig
        // Use the leaf cert + the **original** CA cert from disk (the one users trust)
        let leaf_cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let ca_cert_der = CertificateDer::from(self.ca_cert_der.clone());

        let leaf_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_pair.serialize_der()));

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_cert_der, ca_cert_der], leaf_key_der)?;

        Ok(config)
    }
}

/// Create the standard CA CertificateParams (deterministic, no randomness).
fn create_ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "SimpleProxy CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "SimpleProxy");

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 12, 31);

    params
}

/// Generate a new self-signed CA certificate and key pair.
/// Returns (PEM string, DER bytes, KeyPair).
fn generate_ca() -> Result<(String, Vec<u8>, KeyPair), Box<dyn std::error::Error + Send + Sync>> {
    let params = create_ca_params();
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let cert_der = cert.der().to_vec();

    Ok((cert_pem, cert_der, key_pair))
}

// ─── CA certificate trust verification ───────────────

impl CertManager {
    /// Check whether the CA certificate is installed in the system trust store.
    /// Logs the result and returns `true` if trusted.
    pub fn check_ca_trusted(&self) -> bool {
        let cert_path = self.ca_cert_path();
        info!("[CertManager] Checking if CA certificate is trusted by the system...");

        match is_ca_trusted(&self.ca_cert_der) {
            Ok(true) => {
                info!("[CertManager] ✓ CA certificate is installed and trusted by the system");
                true
            }
            Ok(false) => {
                warn!("[CertManager] ✗ CA certificate is NOT trusted by the system");
                warn!(
                    "[CertManager]   HTTPS interception rules will cause certificate errors in browsers"
                );
                warn!(
                    "[CertManager]   Please install the CA certificate: {}",
                    cert_path.display()
                );
                print_install_instructions(&cert_path);
                false
            }
            Err(e) => {
                warn!("[CertManager] Could not verify CA trust status: {}", e);
                warn!(
                    "[CertManager]   If HTTPS rules don't work, install: {}",
                    cert_path.display()
                );
                false
            }
        }
    }
}

/// Print platform-specific instructions for installing the CA certificate.
fn print_install_instructions(cert_path: &Path) {
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │  CA certificate is NOT installed in the system store    │");
    println!("  │                                                         │");
    println!("  │  HTTPS interception will show security warnings until   │");
    println!("  │  you install the CA certificate.                        │");
    println!("  │                                                         │");
    #[cfg(target_os = "windows")]
    {
        println!("  │  To install (Windows):                                  │");
        println!("  │    1. Double-click the .crt file                        │");
        println!("  │    2. Click 'Install Certificate...'                    │");
        println!("  │    3. Select 'Local Machine' → 'Trusted Root CAs'      │");
        println!("  │                                                         │");
        println!("  │  Or run (as Administrator):                             │");
        println!("  │    certutil -addstore Root \"{}\"", cert_path.display());
    }
    #[cfg(target_os = "macos")]
    {
        println!("  │  To install (macOS):                                    │");
        println!("  │    sudo security add-trusted-cert -d -r trustRoot \\    │");
        println!(
            "  │      -k /Library/Keychains/System.keychain \"{}\"",
            cert_path.display()
        );
    }
    #[cfg(target_os = "linux")]
    {
        println!("  │  To install (Linux):                                    │");
        println!(
            "  │    sudo cp \"{}\" /usr/local/share/ca-certificates/",
            cert_path.display()
        );
        println!("  │    sudo update-ca-certificates                          │");
    }
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();
}

/// Check if the given CA certificate (DER bytes) is trusted by the OS.
fn is_ca_trusted(ca_der: &[u8]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "windows")]
    {
        is_ca_trusted_windows(ca_der)
    }
    #[cfg(target_os = "macos")]
    {
        is_ca_trusted_macos(ca_der)
    }
    #[cfg(target_os = "linux")]
    {
        is_ca_trusted_linux(ca_der)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = ca_der;
        Err("Unsupported platform for trust store check".into())
    }
}

// ─── Windows implementation ──────────────────────────

#[cfg(target_os = "windows")]
fn is_ca_trusted_windows(ca_der: &[u8]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::{Command, Stdio};

    // Write DER to a temp file for PowerShell to load
    let temp_dir = std::env::temp_dir();
    let temp_cert = temp_dir.join("simpleproxy_ca_check.cer");
    fs::write(&temp_cert, ca_der)?;

    // Use PowerShell to compute the thumbprint and search all trust-relevant stores:
    //   - Root     (Trusted Root Certification Authorities)
    //   - AuthRoot (Third-Party Root Certification Authorities)
    //   - CA       (Intermediate Certification Authorities)
    //   × Both LocalMachine and CurrentUser contexts → 6 locations total
    let ps_script = format!(
        r#"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("{path}"); $t = $cert.Thumbprint; $stores = @("Root","AuthRoot","CA"); $found = $false; foreach ($s in $stores) {{ foreach ($loc in @("CurrentUser","LocalMachine")) {{ $c = Get-ChildItem "Cert:\$loc\$s" -ErrorAction SilentlyContinue | Where-Object {{ $_.Thumbprint -eq $t }}; if ($c) {{ $found = $true }} }} }}; if ($found) {{ Write-Output "TRUSTED" }} else {{ Write-Output "NOT_TRUSTED" }}"#,
        path = temp_cert.to_string_lossy().replace('\\', "\\\\")
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let _ = fs::remove_file(&temp_cert);

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            Ok(stdout.trim() == "TRUSTED")
        }
        Err(e) => Err(format!("Failed to run PowerShell: {}", e).into()),
    }
}

// ─── macOS implementation ────────────────────────────

#[cfg(target_os = "macos")]
fn is_ca_trusted_macos(ca_der: &[u8]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    // Write DER to a temp file
    let temp_dir = std::env::temp_dir();
    let temp_cert = temp_dir.join("simpleproxy_ca_check.cer");
    fs::write(&temp_cert, ca_der)?;

    // Use security verify-cert to check trust
    let output = Command::new("security")
        .args(["verify-cert", "-c", &temp_cert.to_string_lossy()])
        .output()?;

    let _ = fs::remove_file(&temp_cert);

    Ok(output.status.success())
}

// ─── Linux implementation ────────────────────────────

#[cfg(target_os = "linux")]
fn is_ca_trusted_linux(ca_der: &[u8]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    // Convert DER to PEM for comparison
    let ca_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ca_der)
    );

    // Write to temp file
    let temp_dir = std::env::temp_dir();
    let temp_cert = temp_dir.join("simpleproxy_ca_check.pem");
    fs::write(&temp_cert, &ca_pem)?;

    // Use openssl to verify against system trust store
    let output = Command::new("openssl")
        .args([
            "verify",
            "-CApath",
            "/etc/ssl/certs",
            &temp_cert.to_string_lossy(),
        ])
        .output()?;

    let _ = fs::remove_file(&temp_cert);

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains(": OK"))
}
