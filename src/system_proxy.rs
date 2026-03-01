//! System proxy configuration support.
//!
//! Automatically sets and restores the system HTTP proxy settings.
//! Supports Windows (registry), macOS (networksetup), and Linux (gsettings/env).

use tracing::{debug, info};

/// Guard that restores the system proxy settings when dropped.
#[allow(dead_code)]
pub struct SystemProxyGuard {
    #[allow(dead_code)]
    restore_fn: Box<dyn FnOnce() + Send>,
}

impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        // The restore function will be called when the guard is dropped.
        // We need to use Option to allow taking ownership in drop.
        info!("Restoring system proxy settings...");
    }
}

/// A droppable guard that uses Option to allow calling FnOnce in drop.
pub struct SystemProxyGuardInner {
    restore_fn: Option<Box<dyn FnOnce() + Send>>,
}

impl Drop for SystemProxyGuardInner {
    fn drop(&mut self) {
        if let Some(f) = self.restore_fn.take() {
            info!("Restoring system proxy settings...");
            f();
        }
    }
}

/// Set the system proxy and return a guard that restores it on drop.
pub fn set_system_proxy(
    host: &str,
    port: u16,
) -> Result<SystemProxyGuardInner, Box<dyn std::error::Error + Send + Sync>> {
    set_system_proxy_platform(host, port)
}

// ─── Windows implementation ──────────────────────────

#[cfg(target_os = "windows")]
fn set_system_proxy_platform(
    host: &str,
    port: u16,
) -> Result<SystemProxyGuardInner, Box<dyn std::error::Error + Send + Sync>> {
    use tracing::error;
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) =
        hkcu.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")?;

    // Save current settings
    let prev_enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
    let prev_server: String = key.get_value("ProxyServer").unwrap_or_default();

    // Set new proxy
    let proxy_server = format!("{}:{}", host, port);
    key.set_value("ProxyEnable", &1u32)?;
    key.set_value("ProxyServer", &proxy_server)?;

    info!("Windows system proxy set to {}", proxy_server);

    // Notify the system of the change
    notify_windows_proxy_change();

    Ok(SystemProxyGuardInner {
        restore_fn: Some(Box::new(move || {
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            if let Ok((key, _)) =
                hkcu.create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            {
                if let Err(e) = key.set_value("ProxyEnable", &prev_enable) {
                    error!("Failed to restore ProxyEnable: {}", e);
                }
                if let Err(e) = key.set_value("ProxyServer", &prev_server) {
                    error!("Failed to restore ProxyServer: {}", e);
                }
                notify_windows_proxy_change();
                debug!(
                    "Windows proxy restored (enable={}, server={})",
                    prev_enable, prev_server
                );
            }
        })),
    })
}

#[cfg(target_os = "windows")]
fn notify_windows_proxy_change() {
    // Use InternetSetOption to notify the system of proxy changes
    use std::ptr;

    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(
            hInternet: *mut std::ffi::c_void,
            dwOption: u32,
            lpBuffer: *mut std::ffi::c_void,
            dwBufferLength: u32,
        ) -> i32;
    }

    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    const INTERNET_OPTION_REFRESH: u32 = 37;

    unsafe {
        InternetSetOptionW(
            ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            ptr::null_mut(),
            0,
        );
        InternetSetOptionW(ptr::null_mut(), INTERNET_OPTION_REFRESH, ptr::null_mut(), 0);
    }
}

// ─── macOS implementation ────────────────────────────

#[cfg(target_os = "macos")]
fn set_system_proxy_platform(
    host: &str,
    port: u16,
) -> Result<SystemProxyGuardInner, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    // Get the active network service
    let output = Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()?;
    let services = String::from_utf8_lossy(&output.stdout);
    let service = services
        .lines()
        .skip(1) // Skip the header line
        .find(|line| !line.starts_with('*')) // Skip disabled services
        .unwrap_or("Wi-Fi")
        .to_string();

    info!("Setting proxy on network service: {}", service);

    // Save current state
    let prev_http = Command::new("networksetup")
        .args(["-getwebproxy", &service])
        .output()?;
    let prev_https = Command::new("networksetup")
        .args(["-getsecurewebproxy", &service])
        .output()?;
    let prev_http_output = String::from_utf8_lossy(&prev_http.stdout).to_string();
    let prev_https_output = String::from_utf8_lossy(&prev_https.stdout).to_string();

    let was_http_enabled = prev_http_output.contains("Enabled: Yes");
    let was_https_enabled = prev_https_output.contains("Enabled: Yes");

    // Set HTTP proxy
    Command::new("networksetup")
        .args(["-setwebproxy", &service, host, &port.to_string()])
        .output()?;

    // Set HTTPS proxy
    Command::new("networksetup")
        .args(["-setsecurewebproxy", &service, host, &port.to_string()])
        .output()?;

    let service_clone = service.clone();
    Ok(SystemProxyGuardInner {
        restore_fn: Some(Box::new(move || {
            if !was_http_enabled {
                let _ = Command::new("networksetup")
                    .args(["-setwebproxystate", &service_clone, "off"])
                    .output();
            }
            if !was_https_enabled {
                let _ = Command::new("networksetup")
                    .args(["-setsecurewebproxystate", &service_clone, "off"])
                    .output();
            }
            debug!("macOS proxy settings restored for {}", service_clone);
        })),
    })
}

// ─── Linux implementation ────────────────────────────

#[cfg(target_os = "linux")]
fn set_system_proxy_platform(
    host: &str,
    port: u16,
) -> Result<SystemProxyGuardInner, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    // Try gsettings (GNOME)
    let gsettings_available = Command::new("which")
        .arg("gsettings")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if gsettings_available {
        // Save current settings
        let prev_mode = Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy", "mode"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "'none'".to_string());

        // Set proxy
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "'manual'"])
            .output();
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.http", "host", host])
            .output();
        let _ = Command::new("gsettings")
            .args([
                "set",
                "org.gnome.system.proxy.http",
                "port",
                &port.to_string(),
            ])
            .output();
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.https", "host", host])
            .output();
        let _ = Command::new("gsettings")
            .args([
                "set",
                "org.gnome.system.proxy.https",
                "port",
                &port.to_string(),
            ])
            .output();

        info!("Linux (GNOME) proxy set to {}:{}", host, port);

        Ok(SystemProxyGuardInner {
            restore_fn: Some(Box::new(move || {
                let _ = Command::new("gsettings")
                    .args(["set", "org.gnome.system.proxy", "mode", &prev_mode])
                    .output();
                debug!("Linux proxy restored to mode: {}", prev_mode);
            })),
        })
    } else {
        // Fallback: just set environment variables (limited scope)
        info!(
            "gsettings not available. Set http_proxy=http://{}:{} manually.",
            host, port
        );
        Ok(SystemProxyGuardInner {
            restore_fn: Some(Box::new(|| {
                debug!("No system proxy to restore (env-only mode)");
            })),
        })
    }
}
