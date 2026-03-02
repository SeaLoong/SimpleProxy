//! Virtual NIC (TUN) Proxy Module
//!
//! Creates a virtual network adapter and proxies TCP/UDP traffic transparently.
//! Uses `tun` for TUN device creation and `ipstack` for userspace TCP/IP stack.
//!
//! # Requirements
//! - Administrator privileges (for TUN device creation and route management)
//! - **Windows**: `wintun.dll` must be in the executable directory or system PATH.
//!   Download from: <https://www.wintun.net/>
//!
//! # Architecture
//! 1. Creates a TUN device with a virtual IP (e.g., 10.0.0.1)
//! 2. Wraps the TUN device with `ipstack` for TCP/UDP stream abstraction
//! 3. For each TCP connection: connects to the real destination and relays data
//! 4. For each UDP packet: forwards to the real destination (DNS-aware)
//! 5. Routes are configured to capture traffic through the virtual NIC

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::upstream;

// ─── Windows: force outbound sockets to a specific interface ────
//
// On Windows, `bind()` only sets the source IP; the routing table still
// controls which interface is used. The `IP_UNICAST_IF` socket option
// bypasses the routing table and forces traffic out a specific NIC,
// preventing the TUN device from re-capturing its own outbound traffic.

#[cfg(target_os = "windows")]
mod win_sock {
    const IPPROTO_IP: i32 = 0;
    const IP_UNICAST_IF: i32 = 31;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(
            s: u64,
            level: i32,
            optname: i32,
            optval: *const u8,
            optlen: i32,
        ) -> i32;
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        /// Returns the best interface index for reaching a given IPv4 address.
        /// `dw_dest_addr` is in **network byte order**.
        fn GetBestInterface(dw_dest_addr: u32, pdw_best_if_index: *mut u32) -> u32;
    }

    /// Force a socket to send traffic through a specific network interface,
    /// bypassing the routing table.
    pub fn set_ip_unicast_if(
        raw_socket: u64,
        if_index: u32,
    ) -> std::io::Result<()> {
        // IP_UNICAST_IF expects the interface index in **network byte order**
        let value = if_index.to_be();
        let ret = unsafe {
            setsockopt(
                raw_socket,
                IPPROTO_IP,
                IP_UNICAST_IF,
                std::ptr::from_ref(&value).cast(),
                4,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Ask the OS which network interface would be used to reach `dest_ip`.
    ///
    /// This uses the Windows `GetBestInterface` API which queries the routing
    /// table and returns the interface index for the best matching route.
    /// Must be called **before** TUN routes are added so it returns the
    /// physical adapter.
    pub fn get_best_interface(
        dest_ip: std::net::Ipv4Addr,
    ) -> std::io::Result<u32> {
        // GetBestInterface expects the IP in network byte order.
        // Ipv4Addr::octets() gives [a, b, c, d]; interpreting those bytes as
        // a native-endian u32 produces the network-byte-order value that the
        // API expects on little-endian Windows.
        let ip_addr = u32::from_ne_bytes(dest_ip.octets());
        let mut if_index: u32 = 0;
        let ret = unsafe { GetBestInterface(ip_addr, &mut if_index) };
        if ret == 0 {
            Ok(if_index)
        } else {
            Err(std::io::Error::from_raw_os_error(ret as i32))
        }
    }
}

/// TUN proxy configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TunConfig {
    /// Whether TUN proxy is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// TUN device IP address (e.g., "10.0.0.1").
    #[serde(default = "default_tun_address")]
    pub address: String,

    /// TUN device netmask (e.g., "255.255.255.0").
    #[serde(default = "default_tun_netmask")]
    pub netmask: String,

    /// Custom DNS server for TUN DNS queries (e.g., "8.8.8.8").
    /// Recommended when capturing all traffic to prevent DNS routing loops.
    #[serde(default = "default_tun_dns")]
    pub dns: Option<String>,

    /// Maximum Transmission Unit (default: 1500).
    #[serde(default = "default_tun_mtu")]
    pub mtu: u32,

    /// List of CIDR routes to capture through the TUN device.
    /// e.g., \["0.0.0.0/0"\] for all traffic, or \["10.0.0.0/8", "172.16.0.0/12"\]
    /// for specific subnets.
    ///
    /// **Important**: When capturing all traffic (0.0.0.0/0), make sure to add
    /// your real gateway/upstream IP to the exclude list to avoid routing loops.
    #[serde(default = "default_tun_routes")]
    pub routes: Vec<String>,

    /// List of IPs or CIDRs to exclude from TUN routing.
    /// Traffic to these destinations will use the default (real) adapter.
    /// Typically includes your upstream proxy IP or default gateway.
    #[serde(default)]
    pub excluded_ips: Vec<String>,
}

fn default_tun_address() -> String {
    "10.0.0.33".to_string()
}
fn default_tun_netmask() -> String {
    "255.255.255.0".to_string()
}
fn default_tun_dns() -> Option<String> {
    Some("8.8.8.8".to_string())
}
fn default_tun_mtu() -> u32 {
    1500
}
fn default_tun_routes() -> Vec<String> {
    vec!["0.0.0.0/0".to_string()]
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: default_tun_address(),
            netmask: default_tun_netmask(),
            dns: default_tun_dns(),
            mtu: default_tun_mtu(),
            routes: default_tun_routes(),
            excluded_ips: Vec::new(),
        }
    }
}

/// Compute a gateway IP for the TUN subnet (first usable IP on the subnet).
/// e.g., address=10.0.0.33, netmask=255.255.255.0 → gateway=10.0.0.1
fn compute_tun_gateway(address: &str, netmask: &str) -> String {
    let addr: Ipv4Addr = address.parse().unwrap_or(Ipv4Addr::new(10, 0, 0, 33));
    let mask: Ipv4Addr = netmask.parse().unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
    let addr_u32 = u32::from(addr);
    let mask_u32 = u32::from(mask);
    let network = addr_u32 & mask_u32;
    let mut gw = network + 1;
    // Ensure gateway is not our own address
    if gw == addr_u32 {
        gw = network + 2;
    }
    Ipv4Addr::from(gw).to_string()
}

/// Expand route list: split 0.0.0.0/0 into two /1 routes for correct precedence.
///
/// This is the standard VPN trick: 0.0.0.0/1 + 128.0.0.0/1 cover all IPs
/// and are more specific than the existing default route 0.0.0.0/0, so they
/// take precedence without replacing it.
fn expand_routes(routes: &[String]) -> Vec<String> {
    let mut expanded = Vec::new();
    for route in routes {
        if route == "0.0.0.0/0" {
            expanded.push("0.0.0.0/1".to_string());
            expanded.push("128.0.0.0/1".to_string());
        } else {
            expanded.push(route.clone());
        }
    }
    expanded
}

/// Detect the physical network adapter's IP address.
///
/// Uses a UDP socket trick: "connecting" a UDP socket to the default
/// gateway determines which local IP the OS selects for outbound traffic.
/// This must be called BEFORE TUN routes are set up.
async fn get_physical_adapter_ip() -> Option<Ipv4Addr> {
    let gateway = get_default_gateway().await?;
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect(format!("{}:53", gateway)).await.ok()?;
    match socket.local_addr() {
        Ok(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                info!("[TUN] Detected physical adapter IP: {}", v4);
                Some(v4)
            }
            _ => None,
        },
        Err(_) => None,
    }
}

/// Detect the physical (non-TUN) network adapter's interface index.
///
/// This is used with `IP_UNICAST_IF` to force outbound traffic through
/// the physical NIC, bypassing the TUN routing table entries.
///
/// Must be called **before** TUN routes are set up so that the routing
/// table still points the default route through the physical adapter.
///
/// Strategy:
///   1. (Primary) `GetBestInterface` Win32 API — asks the OS directly.
///   2. (Fallback) Parse `netsh interface ipv4 show route` output.
#[cfg(target_os = "windows")]
async fn get_physical_interface_index() -> Option<u32> {
    // ── Primary: GetBestInterface API ──────────────────────────────
    // Ask the OS which interface it would use to reach 8.8.8.8.
    // This is the most reliable method.
    match win_sock::get_best_interface(std::net::Ipv4Addr::new(8, 8, 8, 8)) {
        Ok(idx) => {
            info!(
                "[TUN] Detected physical interface index via GetBestInterface: {}",
                idx
            );
            return Some(idx);
        }
        Err(e) => {
            warn!(
                "[TUN] GetBestInterface failed: {}; trying netsh fallback",
                e
            );
        }
    }

    // ── Fallback: parse `netsh interface ipv4 show route` ─────────
    // Note: the `show route` sub-command does NOT accept a filter
    // argument on all Windows versions, so we list ALL routes and
    // search for 0.0.0.0/0 ourselves.
    let output = tokio::process::Command::new("cmd")
        .args(["/C", "netsh interface ipv4 show route"])
        .creation_flags(0x08000000)
        .output()
        .await
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Output format (header + data lines):
    //   Publish  Type   Met  Prefix        Idx  Gateway
    //   -------  -----  ---  ----------    ---  -------
    //   否       手动   0    0.0.0.0/0      17  192.168.2.1
    //
    // Pick the 0.0.0.0/0 route with the *lowest* metric.
    let mut best: Option<(u32, u32)> = None; // (metric, idx)
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            for (i, &part) in parts.iter().enumerate() {
                if part == "0.0.0.0/0" {
                    // Metric is the field before the prefix; Index after.
                    let metric = if i >= 1 {
                        parts[i - 1].parse::<u32>().unwrap_or(u32::MAX)
                    } else {
                        u32::MAX
                    };
                    if let Some(&idx_str) = parts.get(i + 1) {
                        if let Ok(idx) = idx_str.parse::<u32>() {
                            if best.map_or(true, |(m, _)| metric < m) {
                                best = Some((metric, idx));
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some((metric, idx)) = best {
        info!(
            "[TUN] Detected physical interface index via netsh: {} (metric {})",
            idx, metric
        );
        return Some(idx);
    }

    warn!("[TUN] Could not detect physical interface index");
    None
}

/// Non-Windows stub.
#[cfg(not(target_os = "windows"))]
async fn get_physical_interface_index() -> Option<u32> {
    None
}

/// TUN proxy manager.
///
/// Creates a virtual network adapter, captures IP traffic, and proxies
/// TCP/UDP connections through the real network or an upstream proxy.
pub struct TunProxy {
    config: TunConfig,
    running: Arc<AtomicBool>,
    upstream_proxy: Option<String>,
}

impl TunProxy {
    /// Create a new TUN proxy with the given configuration.
    pub fn new(config: TunConfig, upstream_proxy: Option<String>) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            upstream_proxy,
        }
    }

    /// Returns whether the TUN proxy is currently running.
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop the TUN proxy.
    #[allow(dead_code)]
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("[TUN] Stop signal sent");
    }

    /// Start the TUN proxy. This runs until stopped or an error occurs.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            info!("[TUN] Virtual NIC proxy is disabled in config");
            return Ok(());
        }

        info!("[TUN] Starting virtual NIC proxy...");
        info!(
            "[TUN] Address: {}, Netmask: {}, MTU: {}",
            self.config.address, self.config.netmask, self.config.mtu
        );

        // Clean up any stale routes from a previous run that crashed without
        // proper shutdown (otherwise GetBestInterface may return the old TUN).
        info!("[TUN] Cleaning up stale routes from previous runs...");
        if let Err(e) = self.cleanup_routes(
            &compute_tun_gateway(&self.config.address, &self.config.netmask),
        ).await {
            debug!("[TUN] Stale route cleanup (non-fatal): {}", e);
        }

        // Parse IP configuration
        let tun_addr: Ipv4Addr = self
            .config
            .address
            .parse()
            .map_err(|e| format!("Invalid TUN address '{}': {}", self.config.address, e))?;
        let tun_netmask: Ipv4Addr = self
            .config
            .netmask
            .parse()
            .map_err(|e| format!("Invalid TUN netmask '{}': {}", self.config.netmask, e))?;

        // Compute gateway for the TUN subnet (used in route commands)
        let tun_gateway = compute_tun_gateway(&self.config.address, &self.config.netmask);
        let tun_gateway_addr: Ipv4Addr = tun_gateway
            .parse()
            .unwrap_or(Ipv4Addr::new(10, 0, 0, 1));
        info!("[TUN] Computed gateway: {}", tun_gateway);

        // Detect physical adapter info BEFORE creating TUN device / adding routes.
        // physical_ip  : used as bind() source on non-Windows platforms.
        // physical_if  : used with IP_UNICAST_IF on Windows to force outbound
        //                traffic through the physical NIC, bypassing the routing
        //                table's TUN routes.
        let physical_ip = get_physical_adapter_ip().await;
        let physical_if = get_physical_interface_index().await;

        if physical_if.is_some() {
            info!(
                "[TUN] Outbound traffic will use IP_UNICAST_IF to bypass TUN routing"
            );
        } else if physical_ip.is_some() {
            info!(
                "[TUN] IP_UNICAST_IF unavailable; falling back to bind()"
            );
        } else {
            warn!(
                "[TUN] Could not detect physical adapter — routing loops may occur!"
            );
        }

        // Create TUN device configuration
        let mut tun_cfg = tun::Configuration::default();
        tun_cfg
            .address(tun_addr)
            .netmask(tun_netmask)
            .destination(tun_gateway_addr)
            .mtu(self.config.mtu as u16)
            .up();

        // Platform-specific TUN configuration
        #[cfg(target_os = "windows")]
        tun_cfg.platform_config(|p| {
            // Use a fixed GUID so the adapter is reused across restarts
            p.device_guid(0x53696D706C6550726F78795455_u128);
        });

        // Create the TUN device
        let device = tun::create_as_async(&tun_cfg).map_err(|e| {
            format!(
                "Failed to create TUN device: {}. \
                 Ensure running as administrator and wintun.dll is available. \
                 Download wintun.dll from https://www.wintun.net/",
                e
            )
        })?;

        info!("[TUN] Virtual NIC created successfully");

        // Wait for Windows to register the interface before adding routes
        #[cfg(target_os = "windows")]
        {
            info!("[TUN] Waiting for interface registration...");
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }

        // Get TUN interface index for reliable routing
        #[cfg(target_os = "windows")]
        let tun_if_index = get_tun_interface_index().await;
        #[cfg(not(target_os = "windows"))]
        let tun_if_index: Option<u32> = None;

        if let Some(idx) = tun_if_index {
            info!("[TUN] TUN interface index: {}", idx);
        }

        // Configure routes using computed gateway (NOT our own TUN IP)
        if let Err(e) = self.setup_routes(&tun_gateway, tun_if_index).await {
            error!("[TUN] Failed to setup routes: {}", e);
        }

        // Create userspace TCP/IP stack
        let mut ip_stack_config = ipstack::IpStackConfig::default();
        ip_stack_config.mtu(self.config.mtu as u16).map_err(|e| {
            format!("Invalid MTU {}: {}", self.config.mtu, e)
        })?;
        let mut ip_stack = ipstack::IpStack::new(ip_stack_config, device);

        self.running.store(true, Ordering::SeqCst);

        println!();
        println!("========================================");
        println!("  TUN Virtual NIC Proxy started");
        println!(
            "  Virtual adapter: {} / {}",
            self.config.address, self.config.netmask
        );
        if let Some(ref dns) = self.config.dns {
            println!("  DNS server: {}", dns);
        }
        if let Some(idx) = physical_if {
            println!("  Physical NIC IF index: {}", idx);
        }
        if let Some(ref proxy) = self.upstream_proxy {
            println!("  Upstream proxy: {}", proxy);
        }
        if !self.config.routes.is_empty() {
            println!("  Captured routes: {:?}", self.config.routes);
        }
        // Show effective exclusion list (computed during setup_routes)
        {
            let effective = build_exclusion_list(
                &self.config.excluded_ips,
                &self.upstream_proxy,
                &self.config.dns,
            )
            .await;
            if !effective.is_empty() {
                println!("  Excluded IPs: {:?}", effective);
            }
        }
        println!("========================================");
        println!();

        let upstream = self.upstream_proxy.clone();
        let dns = self.config.dns.clone();

        // Main accept loop
        loop {
            if !self.running.load(Ordering::SeqCst) {
                break;
            }

            match ip_stack.accept().await {
                Ok(stream) => {
                    let upstream = upstream.clone();
                    let dns = dns.clone();
                    let phys_if = physical_if;
                    let phys_ip = physical_ip;
                    match stream {
                        ipstack::IpStackStream::Tcp(tcp_stream) => {
                            let dst = tcp_stream.peer_addr();
                            let src = tcp_stream.local_addr();
                            info!(
                                "[TUN] TCP {} -> {}",
                                src, dst
                            );
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_tcp_connection(tcp_stream, dst, upstream, phys_if, phys_ip).await
                                {
                                    debug!("[TUN] TCP error {}: {}", dst, e);
                                }
                            });
                        }
                        ipstack::IpStackStream::Udp(udp_stream) => {
                            let dst = udp_stream.peer_addr();
                            debug!("[TUN] UDP -> {}", dst);
                            tokio::spawn(async move {
                                if let Err(e) = handle_udp_packet(udp_stream, dst, dns, phys_if, phys_ip).await {
                                    debug!("[TUN] UDP error {}: {}", dst, e);
                                }
                            });
                        }
                        ipstack::IpStackStream::UnknownTransport(pkt) => {
                            debug!(
                                "[TUN] Unknown transport packet ({} bytes), dropping",
                                pkt.payload().len()
                            );
                        }
                        ipstack::IpStackStream::UnknownNetwork(pkt) => {
                            debug!(
                                "[TUN] Unknown network packet ({} bytes), dropping",
                                pkt.len()
                            );
                        }
                    }
                }
                Err(e) => {
                    if self.running.load(Ordering::SeqCst) {
                        warn!("[TUN] Accept error: {}", e);
                        // Brief delay to avoid busy-loop on persistent errors
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }

        // Clean up routes on shutdown
        if let Err(e) = self.cleanup_routes(&tun_gateway).await {
            error!("[TUN] Failed to cleanup routes: {}", e);
        }

        self.running.store(false, Ordering::SeqCst);
        info!("[TUN] Virtual NIC proxy stopped");
        Ok(())
    }

    /// Setup IP routes to direct traffic through the TUN device.
    ///
    /// Uses a computed gateway IP (not our own TUN address) and splits
    /// 0.0.0.0/0 into two /1 routes for correct precedence.
    /// Automatically excludes upstream proxy IP, custom DNS server IP, and
    /// user-configured `excluded_ips` to prevent routing loops.
    async fn setup_routes(
        &self,
        gateway: &str,
        tun_if_index: Option<u32>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Build the full exclusion list (config + upstream proxy + custom DNS + system DNS)
        let all_excluded = build_exclusion_list(
            &self.config.excluded_ips,
            &self.upstream_proxy,
            &self.config.dns,
        )
        .await;

        // Add exclusion routes through the real default gateway (no IF index needed)
        if !all_excluded.is_empty() {
            if let Some(real_gateway) = get_default_gateway().await {
                for excluded in &all_excluded {
                    let (network, mask) = parse_cidr(excluded);
                    add_route(&network, &mask, &real_gateway, 1, None).await;
                }
            } else {
                warn!(
                    "[TUN] Could not detect default gateway for exclusion routes. \
                     This may cause routing loops if upstream proxy traffic is captured by TUN!"
                );
            }
        }

        // Expand routes: split 0.0.0.0/0 into 0.0.0.0/1 + 128.0.0.0/1
        let expanded = expand_routes(&self.config.routes);

        // Add capture routes through the TUN gateway (with IF index on Windows)
        for route in &expanded {
            let (network, mask) = parse_cidr(route);
            add_route(&network, &mask, gateway, 3, tun_if_index).await;
        }

        Ok(())
    }

    /// Remove routes that were added during setup.
    async fn cleanup_routes(
        &self,
        gateway: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Expand routes the same way as setup
        let expanded = expand_routes(&self.config.routes);

        for route in &expanded {
            let (network, mask) = parse_cidr(route);
            delete_route(&network, &mask, gateway).await;
        }

        // Rebuild the full excluded list (same logic as setup_routes)
        let all_excluded = build_exclusion_list(
            &self.config.excluded_ips,
            &self.upstream_proxy,
            &self.config.dns,
        )
        .await;

        // Clean up exclusion routes
        if !all_excluded.is_empty() {
            if let Some(real_gateway) = get_default_gateway().await {
                for excluded in &all_excluded {
                    let (network, mask) = parse_cidr(excluded);
                    delete_route(&network, &mask, &real_gateway).await;
                }
            }
        }

        Ok(())
    }
}

// ─── TCP Connection Handler ───────────────────────────────────

/// Handle a proxied TCP connection from the TUN device.
///
/// Connects to the real destination (directly or through upstream proxy)
/// and performs bidirectional data relay.
///
/// On Windows, uses `IP_UNICAST_IF` to force outbound traffic through the
/// physical NIC, bypassing the TUN routing table entries.
async fn handle_tcp_connection<S>(
    tun_stream: S,
    dst: SocketAddr,
    upstream: Option<String>,
    physical_if: Option<u32>,
    physical_ip: Option<Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Helper: create a TcpSocket that is bound to the physical NIC
    // (bypassing TUN routing) and connect it to `addr`.
    let connect_physical = |addr: SocketAddr| async move {
        let socket = tokio::net::TcpSocket::new_v4()?;

        // Windows: use IP_UNICAST_IF to bypass TUN routing table
        #[cfg(target_os = "windows")]
        if let Some(idx) = physical_if {
            use std::os::windows::io::AsRawSocket;
            if let Err(e) = win_sock::set_ip_unicast_if(socket.as_raw_socket(), idx) {
                warn!("[TUN] IP_UNICAST_IF failed for TCP to {}: {}", addr, e);
            }
        }

        // Non-Windows fallback: bind to physical IP
        #[cfg(not(target_os = "windows"))]
        if let Some(ip) = physical_ip {
            socket.bind(SocketAddr::new(std::net::IpAddr::V4(ip), 0))?;
        }

        let _ = physical_if;
        let _ = physical_ip;

        socket.connect(addr).await
    };

    // Connect to the real destination
    let target_stream = if let Some(ref proxy_url) = upstream {
        // Connect through upstream proxy — the TCP connection TO the proxy
        // must ALSO go through the physical NIC, otherwise TUN recaptures it.
        let proxy_info = upstream::parse_proxy_url(proxy_url)?;
        let proxy_addr: SocketAddr = format!("{}:{}", proxy_info.hostname, proxy_info.port)
            .parse()
            .map_err(|e| format!("Invalid proxy address: {}", e))?;

        let proxy_stream = match connect_physical(proxy_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "[TUN] Failed to connect to upstream proxy {}: {}",
                    proxy_addr, e
                );
                return Err(e.into());
            }
        };

        // Perform the proxy handshake (HTTP CONNECT / SOCKS5) on the
        // already-connected, physical-NIC-bound stream.
        match upstream::connect_via_upstream_with_stream(
            proxy_url,
            &dst.ip().to_string(),
            dst.port(),
            proxy_stream,
        )
        .await
        {
            Ok(stream) => stream,
            Err(e) => {
                error!(
                    "[TUN] Proxy handshake failed for {} via {}: {}",
                    dst, proxy_addr, e
                );
                return Err(e);
            }
        }
    } else {
        // Direct connection — force through physical NIC
        match connect_physical(dst).await {
            Ok(stream) => stream,
            Err(e) => {
                debug!("[TUN] Failed to connect to {}: {}", dst, e);
                return Err(e.into());
            }
        }
    };

    debug!("[TUN] TCP connected to {}", dst);

    // Bidirectional data relay using tokio::io::copy
    let (mut tun_read, mut tun_write) = tokio::io::split(tun_stream);
    let (mut target_read, mut target_write) = tokio::io::split(target_stream);

    let client_to_server = async {
        let result = tokio::io::copy(&mut tun_read, &mut target_write).await;
        let _ = target_write.shutdown().await;
        result
    };

    let server_to_client = async {
        let result = tokio::io::copy(&mut target_read, &mut tun_write).await;
        let _ = tun_write.shutdown().await;
        result
    };

    let (c2s, s2c) = tokio::join!(client_to_server, server_to_client);

    let bytes_sent = c2s.unwrap_or(0);
    let bytes_recv = s2c.unwrap_or(0);
    debug!(
        "[TUN] TCP closed {}: sent={}, recv={}",
        dst, bytes_sent, bytes_recv
    );

    Ok(())
}

// ─── UDP Packet Handler ──────────────────────────────────────

/// Handle a UDP packet from the TUN device.
///
/// For DNS queries (port 53), optionally redirects to a custom DNS server.
/// For other UDP, forwards to the original destination.
///
/// On Windows, uses `IP_UNICAST_IF` to force outbound traffic through the
/// physical NIC, bypassing the TUN routing table entries.
async fn handle_udp_packet<S>(
    mut tun_udp: S,
    dst: SocketAddr,
    dns: Option<String>,
    physical_if: Option<u32>,
    physical_ip: Option<Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // For DNS queries (port 53), optionally redirect to custom DNS
    let target_addr = if dst.port() == 53 {
        if let Some(ref dns_server) = dns {
            let addr: SocketAddr = format!("{}:53", dns_server)
                .parse()
                .unwrap_or(dst);
            debug!("[TUN] DNS query redirected to {}", addr);
            addr
        } else {
            dst
        }
    } else {
        dst
    };

    // Create a real UDP socket for forwarding.
    // On Windows, use IP_UNICAST_IF to bypass TUN routing.
    // On non-Windows, bind to physical IP as fallback.
    let real_socket = {
        #[cfg(target_os = "windows")]
        {
            let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
            if let Some(idx) = physical_if {
                use std::os::windows::io::AsRawSocket;
                if let Err(e) = win_sock::set_ip_unicast_if(
                    std_socket.as_raw_socket() as u64,
                    idx,
                ) {
                    warn!(
                        "[TUN] IP_UNICAST_IF failed for UDP to {}: {}",
                        target_addr, e
                    );
                }
            }
            std_socket.set_nonblocking(true)?;
            UdpSocket::from_std(std_socket)?
        }
        #[cfg(not(target_os = "windows"))]
        {
            let bind_ip = physical_ip
                .map(std::net::IpAddr::V4)
                .unwrap_or(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?
        }
    };

    // Suppress unused warnings on platforms where only one branch is compiled
    let _ = physical_if;
    let _ = physical_ip;

    real_socket.connect(target_addr).await?;

    let mut buf = vec![0u8; 65535];

    // Read data from TUN side
    let n = tun_udp.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    // Forward to destination
    real_socket.send(&buf[..n]).await?;

    // Wait for response with timeout
    match tokio::time::timeout(std::time::Duration::from_secs(10), real_socket.recv(&mut buf)).await
    {
        Ok(Ok(n)) => {
            tun_udp.write_all(&buf[..n]).await?;
            debug!(
                "[TUN] UDP {}: {} bytes sent, {} bytes received",
                target_addr,
                buf[..n].len(),
                n
            );
        }
        Ok(Err(e)) => {
            debug!("[TUN] UDP recv error from {}: {}", target_addr, e);
        }
        Err(_) => {
            debug!("[TUN] UDP response timeout from {}", target_addr);
        }
    }

    Ok(())
}

// ─── Route Management Utilities ──────────────────────────────

/// Parse a CIDR notation string (e.g., "10.0.0.0/8") into (network, mask).
fn parse_cidr(cidr: &str) -> (String, String) {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() == 2 {
        let network = parts[0].to_string();
        let prefix_len: u8 = parts[1].parse().unwrap_or(32);
        let mask = prefix_to_netmask(prefix_len);
        (network, mask)
    } else {
        // Treat as single host
        (cidr.to_string(), "255.255.255.255".to_string())
    }
}

/// Convert a CIDR prefix length to a dotted netmask string.
fn prefix_to_netmask(prefix: u8) -> String {
    let mask: u32 = if prefix >= 32 {
        0xFFFFFFFF
    } else if prefix == 0 {
        0
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF,
    )
}

/// Add a route on the system.
/// `if_index` — Optional interface index (Windows `IF <n>`) for reliable TUN routing.
#[cfg(target_os = "windows")]
async fn add_route(network: &str, mask: &str, gateway: &str, metric: u32, if_index: Option<u32>) {
    let mut cmd = format!(
        "route add {} mask {} {} metric {}",
        network, mask, gateway, metric
    );
    if let Some(idx) = if_index {
        cmd.push_str(&format!(" IF {}", idx));
    }
    info!("[TUN] Adding route: {}", cmd);
    match tokio::process::Command::new("cmd")
        .args(["/C", &cmd])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .await
    {
        Ok(output) => {
            if !output.status.success() {
                warn!(
                    "[TUN] Failed to add route: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Err(e) => {
            warn!("[TUN] Failed to run route command: {}", e);
        }
    }
}

/// Add a route (non-Windows stub).
#[cfg(not(target_os = "windows"))]
async fn add_route(network: &str, mask: &str, gateway: &str, metric: u32, _if_index: Option<u32>) {
    info!(
        "[TUN] Route add (not implemented on this platform): {} mask {} via {} metric {}",
        network, mask, gateway, metric
    );
}

/// Delete a route on the system.
#[cfg(target_os = "windows")]
async fn delete_route(network: &str, mask: &str, gateway: &str) {
    let cmd = format!("route delete {} mask {} {}", network, mask, gateway);
    info!("[TUN] Removing route: {}", cmd);
    let _ = tokio::process::Command::new("cmd")
        .args(["/C", &cmd])
        .creation_flags(0x08000000)
        .output()
        .await;
}

/// Delete a route (non-Windows stub).
#[cfg(not(target_os = "windows"))]
async fn delete_route(network: &str, mask: &str, gateway: &str) {
    info!(
        "[TUN] Route delete (not implemented on this platform): {} mask {} via {}",
        network, mask, gateway
    );
}

/// Detect the system's default gateway IP address.
#[cfg(target_os = "windows")]
async fn get_default_gateway() -> Option<String> {
    // Use `route print 0.0.0.0` to find the default gateway
    let output = tokio::process::Command::new("cmd")
        .args(["/C", "route print 0.0.0.0"])
        .creation_flags(0x08000000)
        .output()
        .await
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse the default gateway from route table output
    // Look for lines with "0.0.0.0" as network destination
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
            let gateway = parts[2].to_string();
            info!("[TUN] Detected default gateway: {}", gateway);
            return Some(gateway);
        }
    }

    // Fallback: try `ipconfig` parsing
    let output = tokio::process::Command::new("cmd")
        .args(["/C", "ipconfig"])
        .creation_flags(0x08000000)
        .output()
        .await
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line_trimmed = line.trim();
        if line_trimmed.starts_with("Default Gateway")
            || line_trimmed.starts_with("默认网关")
        {
            if let Some((_key, value)) = line_trimmed.split_once(':') {
                let gw = value.trim().to_string();
                if !gw.is_empty() && gw != "::" {
                    info!("[TUN] Detected default gateway: {}", gw);
                    return Some(gw);
                }
            }
        }
    }

    None
}

/// Detect default gateway (non-Windows stub).
#[cfg(not(target_os = "windows"))]
async fn get_default_gateway() -> Option<String> {
    warn!("[TUN] Default gateway detection not implemented on this platform");
    None
}

/// Detect the system's configured DNS server addresses.
///
/// These must be excluded from TUN routing to avoid DNS resolution loops
/// when capturing all traffic (0.0.0.0/0).
#[cfg(target_os = "windows")]
async fn get_system_dns_servers() -> Vec<String> {
    // Use `netsh interface ip show dnsservers` for reliable DNS detection
    let output = match tokio::process::Command::new("cmd")
        .args(["/C", "netsh interface ip show dnsservers"])
        .creation_flags(0x08000000)
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            warn!("[TUN] Failed to query system DNS servers: {}", e);
            return Vec::new();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut dns_servers = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        // Lines containing DNS IPs look like:
        //   "    1.1.1.1"   or  "DNS servers configured through DHCP: 192.168.1.1"
        // We look for anything that parses as an IPv4 address.
        // Skip IPv6 addresses.
        for word in trimmed.split_whitespace() {
            if let Ok(ip) = word.parse::<Ipv4Addr>() {
                let s = ip.to_string();
                if !dns_servers.contains(&s) {
                    dns_servers.push(s);
                }
            }
        }
    }

    if !dns_servers.is_empty() {
        info!("[TUN] Detected system DNS servers: {:?}", dns_servers);
    }
    dns_servers
}

/// Detect system DNS servers (non-Windows stub).
#[cfg(not(target_os = "windows"))]
async fn get_system_dns_servers() -> Vec<String> {
    // On Linux/macOS, could parse /etc/resolv.conf
    warn!("[TUN] System DNS detection not implemented on this platform");
    Vec::new()
}

/// Build the full exclusion list from config, upstream proxy, custom DNS, and system DNS.
///
/// Returns a list of CIDR strings (host/32) that must bypass TUN routing.
async fn build_exclusion_list(
    config_excluded: &[String],
    upstream_proxy: &Option<String>,
    custom_dns: &Option<String>,
) -> Vec<String> {
    let mut all_excluded: Vec<String> = config_excluded.to_vec();

    // Auto-exclude upstream proxy IP
    if let Some(proxy_url) = upstream_proxy {
        match upstream::parse_proxy_url(proxy_url) {
            Ok(info) => {
                let proxy_host = format!("{}/32", info.hostname);
                if !all_excluded.contains(&proxy_host)
                    && !all_excluded.contains(&info.hostname)
                {
                    info!(
                        "[TUN] Auto-excluding upstream proxy IP: {} (from {})",
                        info.hostname, proxy_url
                    );
                    all_excluded.push(proxy_host);
                }
            }
            Err(e) => {
                warn!(
                    "[TUN] Could not parse upstream proxy URL '{}': {}. \
                     You may need to manually add the proxy IP to excluded_ips!",
                    proxy_url, e
                );
            }
        }
    }

    // Auto-exclude custom DNS server IP
    if let Some(dns_server) = custom_dns {
        let dns_host = format!("{}/32", dns_server);
        if !all_excluded.contains(&dns_host) && !all_excluded.contains(dns_server) {
            info!("[TUN] Auto-excluding custom DNS server: {}", dns_server);
            all_excluded.push(dns_host);
        }
    }

    // Auto-exclude system DNS servers
    let sys_dns = get_system_dns_servers().await;
    for dns in &sys_dns {
        let dns_host = format!("{}/32", dns);
        if !all_excluded.contains(&dns_host) && !all_excluded.contains(dns) {
            info!("[TUN] Auto-excluding system DNS server: {}", dns);
            all_excluded.push(dns_host);
        }
    }

    all_excluded
}

/// Find the wintun interface index from `route print` output.
#[cfg(target_os = "windows")]
async fn get_tun_interface_index() -> Option<u32> {
    let output = tokio::process::Command::new("cmd")
        .args(["/C", "route print"])
        .creation_flags(0x08000000)
        .output()
        .await
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut in_iface_list = false;

    for line in stdout.lines() {
        if line.contains("Interface List") {
            in_iface_list = true;
            continue;
        }
        if in_iface_list {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if trimmed.starts_with("====") {
                continue;
            }
            // Interface list format: "  22...00 ff aa bb ......Wintun Userspace Tunnel"
            let lower = line.to_lowercase();
            if lower.contains("wintun") {
                if let Some(dots) = trimmed.find("...") {
                    if let Ok(idx) = trimmed[..dots].trim().parse::<u32>() {
                        info!("[TUN] Found wintun interface index: {}", idx);
                        return Some(idx);
                    }
                }
            }
        }
    }

    warn!("[TUN] Could not detect wintun interface index from route print");
    None
}

// ─── TUN Manager (hot-reload support) ────────────────────────

/// Thread-safe TUN lifecycle manager.
///
/// Allows starting, stopping, and restarting the TUN proxy at runtime
/// (e.g., from the web dashboard). Holds a reference to the running
/// `TunProxy` instance and its background task handle.
pub struct TunManager {
    /// The stop flag of the currently running TUN proxy (if any).
    running_flag: Mutex<Option<Arc<AtomicBool>>>,
    /// The JoinHandle for the background TUN task (if any).
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl TunManager {
    /// Create a new TUN manager (initially stopped).
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            running_flag: Mutex::new(None),
            task_handle: Mutex::new(None),
        })
    }

    /// Returns whether the TUN proxy is currently running.
    pub async fn is_running(&self) -> bool {
        let flag = self.running_flag.lock().await;
        flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst))
    }

    /// Start the TUN proxy with the given configuration.
    /// If already running, returns an error.
    pub async fn start(
        &self,
        config: TunConfig,
        upstream_proxy: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.is_running().await {
            return Err("TUN proxy is already running".into());
        }

        // Clean up any previous task
        self.stop_inner().await;

        if !config.enabled {
            return Err("TUN proxy is disabled in config".into());
        }

        let tun = TunProxy::new(config, upstream_proxy);
        let flag = Arc::clone(&tun.running);

        let handle = tokio::spawn(async move {
            if let Err(e) = tun.run().await {
                error!("[TUN] Proxy error: {}", e);
            }
        });

        *self.running_flag.lock().await = Some(flag);
        *self.task_handle.lock().await = Some(handle);

        info!("[TUN Manager] TUN proxy started");
        Ok(())
    }

    /// Stop the TUN proxy if running.
    pub async fn stop(&self) {
        if self.is_running().await {
            self.stop_inner().await;
            info!("[TUN Manager] TUN proxy stopped");
        }
    }

    /// Internal stop: signal the running loop to exit and wait for the task.
    async fn stop_inner(&self) {
        // Signal stop
        if let Some(flag) = self.running_flag.lock().await.take() {
            flag.store(false, Ordering::SeqCst);
        }
        // Wait for the task to finish (with timeout)
        if let Some(handle) = self.task_handle.lock().await.take() {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                handle,
            )
            .await;
        }
    }

    /// Restart the TUN proxy with new configuration.
    /// Stops the current instance (if running) and starts a new one.
    pub async fn restart(
        &self,
        config: TunConfig,
        upstream_proxy: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.stop().await;
        // Brief delay to allow OS to release the TUN device
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        self.start(config, upstream_proxy).await
    }

    /// Get a JSON status object for the API.
    #[allow(dead_code)]
    pub async fn status_json(&self) -> String {
        let running = self.is_running().await;
        format!(r#"{{"running":{}}}"#, running)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_to_netmask() {
        assert_eq!(prefix_to_netmask(0), "0.0.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
    }

    #[test]
    fn test_parse_cidr() {
        let (net, mask) = parse_cidr("10.0.0.0/8");
        assert_eq!(net, "10.0.0.0");
        assert_eq!(mask, "255.0.0.0");

        let (net, mask) = parse_cidr("192.168.1.0/24");
        assert_eq!(net, "192.168.1.0");
        assert_eq!(mask, "255.255.255.0");

        let (net, mask) = parse_cidr("1.2.3.4");
        assert_eq!(net, "1.2.3.4");
        assert_eq!(mask, "255.255.255.255");
    }

    #[test]
    fn test_compute_tun_gateway() {
        // Normal case: .33 on /24 → .1
        assert_eq!(compute_tun_gateway("10.0.0.33", "255.255.255.0"), "10.0.0.1");
        // Edge case: address IS .1 → use .2
        assert_eq!(compute_tun_gateway("10.0.0.1", "255.255.255.0"), "10.0.0.2");
        // /16 subnet
        assert_eq!(compute_tun_gateway("172.16.5.10", "255.255.0.0"), "172.16.0.1");
    }

    #[test]
    fn test_expand_routes() {
        // 0.0.0.0/0 is split into two /1 routes
        let expanded = expand_routes(&["0.0.0.0/0".to_string()]);
        assert_eq!(expanded, vec!["0.0.0.0/1", "128.0.0.0/1"]);

        // Specific routes are left unchanged
        let expanded = expand_routes(&["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()]);
        assert_eq!(expanded, vec!["10.0.0.0/8", "172.16.0.0/12"]);

        // Mixed
        let expanded = expand_routes(&[
            "0.0.0.0/0".to_string(),
            "192.168.0.0/16".to_string(),
        ]);
        assert_eq!(expanded, vec!["0.0.0.0/1", "128.0.0.0/1", "192.168.0.0/16"]);
    }

    #[test]
    fn test_default_tun_config() {
        let cfg = TunConfig::default();
        assert_eq!(cfg.dns, Some("8.8.8.8".to_string()));
        assert_eq!(cfg.routes, vec!["0.0.0.0/0".to_string()]);
        assert!(!cfg.enabled);
    }
}
